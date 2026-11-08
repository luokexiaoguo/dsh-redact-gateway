/**
 * Per-session placeholder vault.
 *
 * The mapping "real value ⇄ `[[EMAIL_3]]`" is the only thing that makes a
 * redacted request reversible, so it is both the most sensitive artifact this
 * plugin touches and the one it must never lose: a vault written after the
 * request left would leave the response unreadable, and a plaintext vault would
 * hand the security team's data to anyone who copies the profile directory.
 *
 * Therefore:
 * - at rest the whole mapping is one AES-256-GCM blob with the session id as
 *   additional authenticated data (a file renamed onto another session fails to
 *   decrypt instead of leaking),
 * - the master key lives beside it in a `0600` file, or comes from
 *   `DSH_REDACT_KEY` for teams that push a managed key,
 * - and the file is flushed synchronously *before* the request is dispatched.
 *
 * @module dsh-redact-gateway/vault
 */

import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Envelope version of the on-disk vault. */
const VAULT_VERSION = 1;
/** Additional authenticated data prefix; a rename across sessions breaks decryption. */
const AAD_PREFIX = 'dsh-redact-gateway/v1/';
/** Hard cap on distinct values per session, to bound memory and file size. */
const MAX_ENTRIES = 20000;

/**
 * Restrict a file to its owner. Best effort: Windows ACLs are inherited, so a
 * failure here is reported through the warn sink rather than thrown.
 * @param path - file to protect.
 * @param warn - diagnostic sink.
 */
export function restrictFile(path, warn = () => {}) {
  try {
    chmodSync(path, 0o600);
  } catch (error) {
    warn(`could not restrict permissions of ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Ensure a directory exists and is recursively readable only by its owner.
 * @param dir - directory path.
 * @param warn - diagnostic sink.
 */
export function ensurePrivateDir(dir, warn = () => {}) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch (error) {
    warn(`could not restrict permissions of ${dir}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Decode a master key from its textual form.
 * @param text - base64 or hex encoding of exactly 32 bytes.
 * @returns the key, or `undefined` when the encoding is not a 32-byte key.
 */
function decodeKey(text) {
  const trimmed = text.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, 'hex');
  const base64 = trimmed.replace(/-/g, '+').replace(/_/g, '/');
  try {
    const buffer = Buffer.from(base64, 'base64');
    return buffer.length === 32 ? buffer : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Load the installation's master key, creating one on first use.
 *
 * `DSH_REDACT_KEY` wins when set so a fleet can rotate keys without touching
 * every profile directory; otherwise a random key is generated once and stored
 * next to the vaults.
 * @param dataDir - plugin data directory.
 * @param warn - diagnostic sink.
 */
export function ensureMasterKey(dataDir, warn = () => {}) {
  const configured = process.env.DSH_REDACT_KEY;
  if (typeof configured === 'string' && configured.trim().length > 0) {
    const key = decodeKey(configured);
    if (key === undefined) {
      warn('DSH_REDACT_KEY is not a 32-byte base64/hex key; falling back to the local key file');
    } else {
      return { key, source: 'env' };
    }
  }

  ensurePrivateDir(dataDir, warn);
  const keyPath = join(dataDir, 'master.key');
  if (existsSync(keyPath)) {
    const key = decodeKey(readFileSync(keyPath, 'utf8'));
    if (key !== undefined) return { key, source: 'file' };
    warn('the local master key is malformed and was regenerated; existing vaults become unreadable');
  }
  const key = randomBytes(32);
  writeFileSync(keyPath, `${key.toString('base64')}\n`, { mode: 0o600 });
  restrictFile(keyPath, warn);
  return { key, source: 'file' };
}

/**
 * Encrypt one JSON payload into the on-disk envelope.
 * @param plaintext - serialized mapping.
 * @param key - 32-byte AES key.
 * @param aad - additional authenticated data.
 */
function seal(plaintext, key, aad) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    v: VAULT_VERSION,
    alg: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: data.toString('base64'),
  };
}

/**
 * Decrypt one on-disk envelope.
 * @param envelope - parsed envelope.
 * @param key - 32-byte AES key.
 * @param aad - additional authenticated data.
 * @returns the parsed mapping.
 */
function open(envelope, key, aad) {
  if (typeof envelope !== 'object' || envelope === null || envelope.alg !== 'aes-256-gcm') {
    throw new Error('vault envelope is not an AES-256-GCM payload');
  }
  const iv = Buffer.from(String(envelope.iv), 'base64');
  const tag = Buffer.from(String(envelope.tag), 'base64');
  if (iv.length !== 12 || tag.length !== 16) throw new Error('vault envelope has malformed IV or tag');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(String(envelope.data), 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString('utf8'));
}

/**
 * One session's placeholder mapping.
 */
export class Vault {
  #sessionId;
  #key;
  #file;
  #degraded;
  #warn;
  #entries = [];
  #byValue = new Map();
  #byPlaceholder = new Map();
  #counters = new Map();
  #dirty = false;
  #createdAt = Date.now();
  #updatedAt = Date.now();
  #dropped = 0;

  /**
   * @param options.sessionId - session whose log the placeholders belong to.
   * @param options.file - absolute vault path.
   * @param options.key - 32-byte AES key.
   * @param options.degraded - keep the mapping in memory only.
   * @param options.warn - diagnostic sink.
   */
  constructor({ sessionId, file, key, degraded, warn = () => {} }) {
    this.#sessionId = sessionId;
    this.#file = file;
    this.#key = key;
    this.#degraded = degraded;
    this.#warn = warn;
  }

  /**
   * Open (or create) one session vault.
   * @param options.dir - directory holding session vaults.
   * @param options.sessionId - session id.
   * @param options.key - master key.
   * @param options.degraded - never touch disk.
   * @param options.warn - diagnostic sink.
   * @returns the loaded vault.
   */
  static open({ dir, sessionId, key, degraded = false, warn = () => {} }) {
    const file = degraded ? '' : join(dir, 'sessions', `${sanitizeSessionId(sessionId)}.vault`);
    const vault = new Vault({ sessionId, file, key, degraded, warn });
    vault.#load();
    return vault;
  }

  /** @returns how many distinct values this session has masked. */
  get size() {
    return this.#entries.length;
  }

  /** @returns whether the mapping is memory-only. */
  get degraded() {
    return this.#degraded;
  }

  /** @returns the vault path, or an empty string in memory-only mode. */
  get path() {
    return this.#file;
  }

  /** Load the encrypted mapping when the file exists and decrypts. */
  #load() {
    if (this.#degraded || this.#file.length === 0 || !existsSync(this.#file)) return;
    let envelope;
    try {
      envelope = JSON.parse(readFileSync(this.#file, 'utf8'));
    } catch (error) {
      this.#warn(`vault ${this.#file} is unreadable and was set aside: ${describe(error)}`);
      this.#aside();
      return;
    }
    try {
      const payload = open(envelope, this.#key, `${AAD_PREFIX}${this.#sessionId}`);
      this.#restore(payload);
    } catch (error) {
      // A key rotation or a copied profile lands here. Keeping the file lets an
      // operator recover with the old key, so it is set aside, not deleted.
      this.#warn(`vault ${this.#file} could not be decrypted (${describe(error)}); placeholders restart from zero`);
      this.#aside();
    }
  }

  /** Rename an unusable vault next to itself so a later run cannot overwrite it. */
  #aside() {
    try {
      const moved = `${this.#file}.unreadable-${Date.now()}`;
      renameSync(this.#file, moved);
      this.#warn(`unreadable vault moved to ${moved}`);
    } catch (error) {
      this.#warn(`could not move the unreadable vault aside: ${describe(error)}`);
    }
  }

  /** Restore counters, entries, and indexes from a decrypted payload. */
  #restore(payload) {
    if (typeof payload !== 'object' || payload === null || payload.v !== VAULT_VERSION) return;
    if (payload.sessionId !== this.#sessionId) {
      this.#warn('vault belongs to another session and was ignored');
      return;
    }
    this.#createdAt = typeof payload.createdAt === 'number' ? payload.createdAt : this.#createdAt;
    this.#updatedAt = typeof payload.updatedAt === 'number' ? payload.updatedAt : this.#updatedAt;
    if (Array.isArray(payload.entries)) {
      for (const entry of payload.entries) {
        if (typeof entry !== 'object' || entry === null) continue;
        const { c, i, v, h } = entry;
        if (typeof c !== 'string' || !Number.isSafeInteger(i) || typeof v !== 'string') continue;
        const placeholder = this.formatPlaceholder(c, i);
        this.#entries.push({ category: c, index: i, value: v, hits: typeof h === 'number' ? h : 0 });
        this.#byValue.set(vaultKey(c, v), { category: c, index: i, placeholder });
        this.#byPlaceholder.set(placeholder, v);
        const current = this.#counters.get(c) ?? 0;
        if (i > current) this.#counters.set(c, i);
      }
    }
  }

  /**
   * Render the placeholder text for one category/index pair.
   * @param category - detector category.
   * @param index - 1-based per-category number.
   */
  formatPlaceholder(category, index) {
    return this.#placeholderOf(category, index);
  }

  /** Placeholder delimiter source, injected by the gateway before first use. */
  #delimiters = { open: '[[', close: ']]' };

  /**
   * Set the delimiters configured for this installation.
   *
   * Rebuilds the reverse index, because entries restored from disk were indexed
   * with whatever delimiters were active at construction time.
   * @param delimiters - opening and closing text.
   */
  setDelimiters(delimiters) {
    this.#delimiters = delimiters;
    this.#byPlaceholder.clear();
    for (const entry of this.#entries) {
      const placeholder = this.#placeholderOf(entry.category, entry.index);
      this.#byPlaceholder.set(placeholder, entry.value);
      const indexed = this.#byValue.get(vaultKey(entry.category, entry.value));
      if (indexed !== undefined) indexed.placeholder = placeholder;
    }
  }

  /** Render a placeholder with the configured delimiters. */
  #placeholderOf(category, index) {
    return `${this.#delimiters.open}${category.toUpperCase()}_${index}${this.#delimiters.close}`;
  }

  /**
   * Return the placeholder for one value, minting a new number on first sight.
   *
   * Repeated occurrences reuse the same placeholder so the model sees one token
   * per distinct value and the mapping stays small.
   * @param category - detector category.
   * @param value - the exact original text.
   * @returns the placeholder text and whether this call minted it.
   */
  placeholder(category, value) {
    const existing = this.#byValue.get(vaultKey(category, value));
    if (existing !== undefined) {
      const entry = this.#entries.find((item) => item.category === category && item.index === existing.index);
      if (entry !== undefined) entry.hits += 1;
      this.#updatedAt = Date.now();
      this.#dirty = true;
      return { placeholder: existing.placeholder, created: false };
    }
    if (this.#entries.length >= MAX_ENTRIES) {
      this.#dropped += 1;
      if (this.#dropped === 1) {
        this.#warn(`session ${this.#sessionId} reached ${MAX_ENTRIES} masked values; further values reuse their own text`);
      }
      return { placeholder: value, created: false };
    }
    const index = (this.#counters.get(category) ?? 0) + 1;
    this.#counters.set(category, index);
    const placeholder = this.#placeholderOf(category, index);
    this.#entries.push({ category, index, value, hits: 1 });
    this.#byValue.set(vaultKey(category, value), { category, index, placeholder });
    this.#byPlaceholder.set(placeholder, value);
    this.#updatedAt = Date.now();
    this.#dirty = true;
    return { placeholder, created: true };
  }

  /**
   * Resolve one placeholder back to its original value.
   * @param placeholder - exact placeholder text.
   */
  resolve(placeholder) {
    return this.#byPlaceholder.get(placeholder);
  }

  /** @returns the number of distinct masked values, per category. */
  countsByCategory() {
    const counts = {};
    for (const entry of this.#entries) counts[entry.category] = (counts[entry.category] ?? 0) + 1;
    return counts;
  }

  /** @returns every mapping entry, newest last. */
  entries() {
    return this.#entries.map((entry) => ({ ...entry }));
  }

  /**
   * Write the mapping to disk now.
   *
   * Called synchronously before dispatch: a mapping that arrives after the
   * request cannot restore the response.
   * @param force - write even when nothing changed.
   * @returns whether the file on disk is current.
   */
  flush(force = false) {
    if (this.#degraded) return false;
    if (!this.#dirty && !force) return true;
    const payload = {
      v: VAULT_VERSION,
      sessionId: this.#sessionId,
      createdAt: this.#createdAt,
      updatedAt: this.#updatedAt,
      entries: this.#entries.map((entry) => ({ c: entry.category, i: entry.index, v: entry.value, h: entry.hits })),
    };
    try {
      ensurePrivateDir(join(this.#file, '..'), this.#warn);
      const sealed = seal(JSON.stringify(payload), this.#key, `${AAD_PREFIX}${this.#sessionId}`);
      const temporary = `${this.#file}.tmp`;
      writeFileSync(temporary, JSON.stringify(sealed), { mode: 0o600 });
      restrictFile(temporary, this.#warn);
      renameSync(temporary, this.#file);
      this.#dirty = false;
      return true;
    } catch (error) {
      this.#degraded = true;
      this.#warn(`vault ${this.#file} could not be written (${describe(error)}); this session continues in memory only`);
      try {
        rmSync(`${this.#file}.tmp`, { force: true });
      } catch {
        /* the temporary file is already gone */
      }
      return false;
    }
  }

  /** Encrypt and read back the file once, proving the key and the medium work. */
  selfTest() {
    if (this.#degraded) return false;
    const probe = seal(JSON.stringify({ probe: true }), this.#key, `${AAD_PREFIX}self-test`);
    try {
      const restored = open(probe, this.#key, `${AAD_PREFIX}self-test`);
      return restored?.probe === true;
    } catch {
      return false;
    }
  }

  /** Drop decrypted material; the file stays for the audit trail. */
  dispose() {
    this.flush();
    this.#entries = [];
    this.#byValue.clear();
    this.#byPlaceholder.clear();
    this.#counters.clear();
  }
}

/** Map key for one value inside one category. */
function vaultKey(category, value) {
  return `${category}\u0000${value}`;
}

/** Keep a session id from escaping the vault directory. */
function sanitizeSessionId(sessionId) {
  const cleaned = String(sessionId).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 96);
  return cleaned.length > 0 ? cleaned : 'unknown';
}

/** Render an unknown caught value without leaking payloads. */
function describe(error) {
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * Constant-time comparison of two placeholder strings.
 * @param a - one string.
 * @param b - the other.
 */
export function placeholderEquals(a, b) {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Read one file's size, for the status surface.
 * @param path - file to stat.
 */
export function fileSize(path) {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}
