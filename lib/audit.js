/**
 * Tamper-evident audit log.
 *
 * A security team's first question about a redaction gateway is "prove it
 * ran, and prove nobody edited the record". Two design choices answer it:
 *
 * 1. **The log never contains an original value.** Identity numbers and phone
 *    numbers live in a space small enough to brute-force from a plain salted
 *    hash in seconds, so each record carries a keyed HMAC fingerprint
 *    (`k_fp`, distinct from the vault's encryption key) plus a short mask. That
 *    makes an exported CSV safe to email internally while still supporting
 *    "was this the same ID that appeared last month?".
 * 2. **Records chain.** Every line embeds the hash of the previous line, so a
 *    deleted or rewritten record breaks verification from that point on.
 *
 * @module dsh-redact-gateway/audit
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { ensurePrivateDir, restrictFile } from './vault.js';

/** Separator that makes two concatenated values unambiguous inside a hash. */
const HASH_SEPARATOR = '\u0000';
/** Cells Excel would execute are prefixed with an apostrophe. */
const CSV_INJECTION = /^[=+\-@\t\r\n＝＋－＠]/;

const CSV_COLUMNS = Object.freeze([
  'seq',
  'timestamp_utc',
  'timestamp_local',
  'session_id',
  'workspace_fp',
  'provider',
  'model',
  'purpose',
  'direction',
  'action',
  'category',
  'rule_id',
  'placeholder',
  'mask',
  'value_fp',
  'value_shape',
  'validation',
  'occurrences',
  'outcome',
  'prev_hash',
  'record_hash',
]);

/**
 * Load the audit fingerprint key, creating it on first use.
 * @param dataDir - plugin data directory.
 * @param warn - diagnostic sink.
 */
export function ensureFingerprintKey(dataDir, warn = () => {}) {
  ensurePrivateDir(dataDir, warn);
  const path = join(dataDir, 'fingerprint.key');
  if (existsSync(path)) {
    const raw = readFileSync(path, 'utf8').trim();
    const base64 = raw.replace(/-/g, '+').replace(/_/g, '/');
    try {
      const key = Buffer.from(base64, 'base64');
      if (key.length === 32) return key;
    } catch {
      /* fall through to regeneration */
    }
    warn('the audit fingerprint key is malformed and was regenerated; past fingerprints stop matching');
  }
  const key = randomBytes(32);
  writeFileSync(path, `${key.toString('base64')}\n`, { mode: 0o600 });
  restrictFile(path, warn);
  return key;
}

/**
 * Mask a value for human review: enough shape to recognise, not enough to reuse.
 * @param value - original text.
 * @param category - detector category.
 */
export function maskValue(value, category) {
  const text = String(value);
  if (text.length === 0) return '';
  if (category === 'email') {
    const at = text.lastIndexOf('@');
    if (at > 0) {
      const local = text.slice(0, at);
      const domain = text.slice(at);
      return `${local.slice(0, 1)}${'*'.repeat(Math.min(3, Math.max(1, local.length - 1)))}${domain}`;
    }
  }
  if (text.length <= 4) return `${text.slice(0, 1)}${'*'.repeat(text.length - 1)}`;
  const keep = text.length >= 11 ? 3 : 2;
  return `${text.slice(0, keep)}${'*'.repeat(Math.max(4, text.length - keep - 3))}${text.slice(-3)}`;
}

/** Serialize one record's hashed fields deterministically. */
function canonical(record) {
  return JSON.stringify([
    record.seq,
    record.ts,
    record.sessionId,
    record.workspaceFp,
    record.provider,
    record.model,
    record.purpose,
    record.direction,
    record.action,
    record.category,
    record.ruleId,
    record.placeholder,
    record.mask,
    record.valueFp,
    record.valueShape,
    record.validation,
    record.count,
    record.outcome,
  ]);
}

/** Chain hash: previous hash and the canonical record body, unambiguous order. */
function chainHash(prev, record) {
  return createHash('sha256').update(prev).update(HASH_SEPARATOR).update(canonical(record)).digest('hex');
}

/** Month bucket used for file names. */
function monthBucket(date) {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  return `${year}-${month}`;
}

/**
 * One installation's audit log.
 */
export class AuditLog {
  #dir;
  #fingerprintKey;
  #retentionDays;
  #maskEnabled;
  #seq = 0;
  #head = 'genesis';
  #warn;
  #stats = { requests: 0, placeholders: 0, blocked: 0, lastAt: 0, byCategory: {} };
  #totalsPath;

  /**
   * @param options.dir - audit directory (created on demand).
   * @param options.fingerprintKey - 32-byte HMAC key for value fingerprints.
   * @param options.retentionDays - months older than this are removed.
   * @param options.mask - whether to include the human-readable mask column.
   * @param options.warn - diagnostic sink.
   */
  constructor({ dir, fingerprintKey, retentionDays, mask, warn = () => {} }) {
    this.#dir = dir;
    this.#fingerprintKey = fingerprintKey;
    this.#retentionDays = retentionDays;
    this.#maskEnabled = mask;
    this.#warn = warn;
    this.#totalsPath = join(dir, 'stats.json');
  }

  /**
   * Open the log, restore the chain head, and prune expired files.
   * @param options - see the constructor.
   * @returns the opened log.
   */
  static open(options) {
    ensurePrivateDir(options.dir, options.warn);
    const log = new AuditLog(options);
    log.#restoreHead();
    log.#loadStats();
    log.#prune();
    return log;
  }

  /** @returns the current chain head, for out-of-band checkpointing. */
  get head() {
    return this.#head;
  }

  /** @returns running counters since this process started plus the persisted lifetime totals. */
  stats() {
    return {
      requests: this.#stats.requests,
      placeholders: this.#stats.placeholders,
      blocked: this.#stats.blocked,
      lastAt: this.#stats.lastAt,
      byCategory: { ...this.#stats.byCategory },
      head: this.#head,
    };
  }

  /** Read the newest log line so appends continue the same chain. */
  #restoreHead() {
    const files = this.#files();
    if (files.length === 0) return;
    const last = files[files.length - 1];
    try {
      const text = readFileSync(join(this.#dir, last), 'utf8').trimEnd();
      if (text.length === 0) return;
      const lines = text.split('\n');
      const tail = JSON.parse(lines[lines.length - 1]);
      if (typeof tail.seq === 'number') this.#seq = tail.seq;
      if (typeof tail.hash === 'string') this.#head = tail.hash;
    } catch (error) {
      this.#warn(`audit chain head could not be restored from ${last}: ${describe(error)}`);
    }
  }

  /** Load persisted lifetime counters. */
  #loadStats() {
    try {
      const parsed = JSON.parse(readFileSync(this.#totalsPath, 'utf8'));
      if (typeof parsed === 'object' && parsed !== null) {
        this.#stats = {
          requests: Number.isFinite(parsed.requests) ? parsed.requests : 0,
          placeholders: Number.isFinite(parsed.placeholders) ? parsed.placeholders : 0,
          blocked: Number.isFinite(parsed.blocked) ? parsed.blocked : 0,
          lastAt: Number.isFinite(parsed.lastAt) ? parsed.lastAt : 0,
          byCategory: typeof parsed.byCategory === 'object' && parsed.byCategory !== null ? { ...parsed.byCategory } : {},
        };
      }
    } catch {
      /* first run: no counters yet */
    }
  }

  /** Persist lifetime counters; cheap enough to run after every request. */
  persistStats() {
    try {
      writeFileSync(this.#totalsPath, JSON.stringify(this.#stats), { mode: 0o600 });
    } catch (error) {
      this.#warn(`audit counters could not be written: ${describe(error)}`);
    }
  }

  /** Delete month files that fell out of the retention window. */
  #prune() {
    if (!(this.#retentionDays > 0)) return;
    const cutoff = Date.now() - this.#retentionDays * 24 * 60 * 60 * 1000;
    for (const file of this.#files().filter((name) => /^\d{4}-\d{2}\.jsonl$/.test(name))) {
      const [year, month] = file.replace('.jsonl', '').split('-').map(Number);
      const boundary = Date.UTC(year, month, 1);
      if (boundary >= cutoff) continue;
      try {
        rmSync(join(this.#dir, file), { force: true });
      } catch (error) {
        this.#warn(`expired audit file ${file} could not be removed: ${describe(error)}`);
      }
    }
  }

  /** @returns the JSONL file names present, ascending. */
  #files() {
    try {
      return readdirSync(this.#dir).filter((name) => name.endsWith('.jsonl')).sort();
    } catch {
      return [];
    }
  }

  /**
   * Compute the audit fingerprint of one value.
   * @param value - original text.
   */
  fingerprint(value) {
    return createHmac('sha256', this.#fingerprintKey)
      .update('fp:v1:')
      .update(String(value))
      .digest('hex')
      .slice(0, 32);
  }

  /**
   * Compute the workspace fingerprint so exported paths do not name projects.
   * @param path - absolute working directory.
   */
  workspaceFingerprint(path) {
    if (typeof path !== 'string' || path.length === 0) return '';
    return createHmac('sha256', this.#fingerprintKey).update('ws:v1:').update(path).digest('hex').slice(0, 16);
  }

  /**
   * Append one redaction record.
   * @param entry - the event to record.
   * @returns the stored record, including its chain fields.
   */
  record(entry) {
    const now = new Date(entry.timestamp ?? Date.now());
    this.#seq += 1;
    const record = {
      seq: this.#seq,
      ts: now.toISOString(),
      sessionId: entry.sessionId ?? '',
      workspaceFp: entry.workspaceFp ?? '',
      provider: entry.provider ?? '',
      model: entry.model ?? '',
      purpose: entry.purpose ?? '',
      direction: entry.direction ?? 'request',
      action: entry.action ?? 'redact',
      category: entry.category ?? '',
      ruleId: entry.ruleId ?? '',
      placeholder: entry.placeholder ?? '',
      mask: this.#maskEnabled ? (entry.mask ?? '') : '',
      valueFp: entry.valueFp ?? '',
      valueShape: entry.valueShape ?? '',
      validation: entry.validation ?? 'none',
      count: Number.isFinite(entry.count) ? entry.count : 1,
      outcome: entry.outcome ?? 'redacted',
    };
    const prev = this.#head;
    const hash = chainHash(prev, record);
    const stored = {
      ...record,
      tsLocal: now.toISOString(),
      prev,
      hash,
    };
    try {
      ensurePrivateDir(this.#dir, this.#warn);
      appendFileSync(join(this.#dir, `${monthBucket(now)}.jsonl`), `${JSON.stringify(stored)}\n`, { mode: 0o600 });
      this.#head = hash;
    } catch (error) {
      // Losing an audit line must not lose the request, but it must be loud.
      this.#warn(`audit record could not be appended: ${describe(error)}`);
    }
    return stored;
  }

  /** Fold one request's counters into the running totals. */
  observe({ placeholders = 0, blocked = 0, byCategory = {} }) {
    this.#stats.requests += 1;
    this.#stats.placeholders += placeholders;
    this.#stats.blocked += blocked;
    this.#stats.lastAt = Date.now();
    for (const [category, count] of Object.entries(byCategory)) {
      this.#stats.byCategory[category] = (this.#stats.byCategory[category] ?? 0) + count;
    }
  }

  /**
   * Read records within a window.
   * @param filter - optional `since`/`until` (epoch ms), `category`, `sessionId`, `limit`.
   * @returns the matching records, oldest first.
   */
  query(filter = {}) {
    const since = Number.isFinite(filter.since) ? filter.since : 0;
    const until = Number.isFinite(filter.until) ? filter.until : Number.MAX_SAFE_INTEGER;
    const limit = Number.isFinite(filter.limit) ? filter.limit : 500;
    const rows = [];
    for (const file of this.#files().filter((name) => /^\d{4}-\d{2}\.jsonl$/.test(name))) {
      let text;
      try {
        text = readFileSync(join(this.#dir, file), 'utf8');
      } catch {
        continue;
      }
      for (const line of text.split('\n')) {
        if (line.length === 0) continue;
        let record;
        try {
          record = JSON.parse(line);
        } catch {
          continue;
        }
        const at = Date.parse(record.ts);
        if (Number.isFinite(at)) {
          if (at < since || at > until) continue;
        }
        if (filter.category !== undefined && record.category !== filter.category) continue;
        if (filter.sessionId !== undefined && record.sessionId !== filter.sessionId) continue;
        rows.push(record);
      }
    }
    return rows.length > limit ? rows.slice(rows.length - limit) : rows;
  }

  /**
   * Verify the hash chain of the stored records.
   * @returns whether every link is intact, and the first broken sequence number.
   */
  verifyChain() {
    let previous = 'genesis';
    let expectedSeq = 0;
    for (const file of this.#files()) {
      let text;
      try {
        text = readFileSync(join(this.#dir, file), 'utf8');
      } catch {
        continue;
      }
      for (const line of text.split('\n')) {
        if (line.length === 0) continue;
        let record;
        try {
          record = JSON.parse(line);
        } catch {
          return { ok: false, brokenAt: expectedSeq + 1, reason: 'unparsable line' };
        }
        if (expectedSeq !== 0 && record.seq !== expectedSeq + 1) {
          return { ok: false, brokenAt: record.seq, reason: 'sequence gap' };
        }
        const recomputed = chainHash(previous, record);
        if (recomputed !== record.hash) {
          return { ok: false, brokenAt: record.seq, reason: 'hash mismatch' };
        }
        previous = record.hash;
        expectedSeq = record.seq;
      }
    }
    return { ok: true, records: expectedSeq, head: previous };
  }

  /**
   * Export matching records as CSV.
   * @param filter - same filter shape as `query`.
   * @param outPath - absolute path of the file to write.
   * @returns the written path, row count, and the CSV text for direct download.
   */
  exportCsv(filter, outPath) {
    const rows = this.query({ ...filter, limit: Number.isFinite(filter?.limit) ? filter.limit : 200000 });
    const lines = [CSV_COLUMNS.map(csvCell).join(',')];
    for (const row of rows) {
      lines.push(
        [
          row.seq,
          row.ts,
          row.tsLocal,
          row.sessionId,
          row.workspaceFp,
          row.provider,
          row.model,
          row.purpose,
          row.direction,
          row.action,
          row.category,
          row.ruleId,
          row.placeholder,
          row.mask,
          row.valueFp,
          row.valueShape,
          row.validation,
          row.count,
          row.outcome,
          row.prev,
          row.hash,
        ]
          .map(csvCell)
          .join(','),
      );
    }
    // Excel needs the BOM to read UTF-8 Chinese; every other tool tolerates it.
    const csv = `\uFEFF${lines.join('\r\n')}\r\n`;
    let written = '';
    if (typeof outPath === 'string' && outPath.length > 0) {
      try {
        ensurePrivateDir(join(outPath, '..'), this.#warn);
        writeFileSync(outPath, csv, { mode: 0o600 });
        restrictFile(outPath, this.#warn);
        written = outPath;
      } catch (error) {
        this.#warn(`audit export could not be written to ${outPath}: ${describe(error)}`);
      }
    }
    return { path: written, rows: rows.length, csv };
  }
}

/**
 * Render one CSV cell: always quoted, and neutralized against formula injection.
 * @param value - cell value.
 */
function csvCell(value) {
  const text = value === undefined || value === null ? '' : String(value);
  const neutralized = CSV_INJECTION.test(text) ? `'${text}` : text;
  return `"${neutralized.replace(/"/g, '""')}"`;
}

/** Render an unknown caught value without leaking payloads. */
function describe(error) {
  if (error instanceof Error) return error.message;
  return String(error);
}
