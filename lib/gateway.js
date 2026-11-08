/**
 * The egress gateway: one `llm/stream` interceptor that masks a request, sends
 * the masked copy, and restores the response.
 *
 * Why it re-dispatches instead of rewriting in place: the agent loop hands the
 * request to the waterfall already frozen (`Object.freeze(request)` plus
 * `deepFreeze(message)`), and `next()` accepts no replacement arguments. The
 * only supported way to change what leaves the machine is to build a new
 * request and drive it through a prepared call, so that is what happens here.
 *
 * The re-dispatch necessarily re-enters `llm/stream`; a per-object guard makes
 * the second pass fall through to `next()`, so every other listener on the
 * seam — title generation, checkpoint durability, metrics — still runs exactly
 * once, against the masked request.
 *
 * @module dsh-redact-gateway/gateway
 */

import { readdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { resolveWorkspacePolicy } from './config.js';
import { createDetector } from './rules.js';
import { Rehydrator, rehydrateText } from './stream.js';
import { createRedactor } from './redact.js';
import { Vault, ensureMasterKey, ensurePrivateDir } from './vault.js';
import { AuditLog, ensureFingerprintKey, maskValue } from './audit.js';

/** Error code surfaced to the turn when protection cannot be guaranteed. */
const FAILURE_CODE = 'REDACT_GATEWAY_FAILED';
/** Delimiters used for the fail-closed diagnostic, independent of config. */
const MAX_SESSIONS = 64;

/** Render an unknown caught value without leaking request payloads. */
function describe(error) {
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * The gateway instance owned by one plugin activation.
 */
export class Gateway {
  #ctx;
  #config;
  #warn;
  #log;
  #paths;
  #encKey;
  #fpKey;
  #audit;
  #vaults = new Map();
  #detectors = new Map();
  #guard = new WeakSet();
  #depth = 0;
  #pausedUntil = 0;
  #sessions = new Map();
  #lastMask = [];
  #skipNoted = new Map();
  /** Placeholders already recorded in this process, per session, for dedupe. */
  #seenPlaceholders = new Map();
  #persistTimer;
  #pendingPatch = {};
  #disposed = false;
  #vaultTtlHours;

  /**
   * @param options.ctx - plugin context.
   * @param options.config - normalized config.
   * @param options.paths - resolved data directories.
   * @param options.warn - diagnostic sink (never receives message content).
   * @param options.log - the host logger.
   */
  constructor({ ctx, config, paths, warn, log }) {
    this.#ctx = ctx;
    this.#config = config;
    this.#paths = paths;
    this.#warn = warn;
    this.#log = log;
    this.#vaultTtlHours = Number.isFinite(paths.vaultTtlHours) ? paths.vaultTtlHours : 168;

    ensurePrivateDir(paths.root, warn);
    ensurePrivateDir(paths.sessions, warn);
    const master = ensureMasterKey(paths.root, warn);
    this.#encKey = master.key;

    this.#audit = AuditLog.open({
      dir: paths.audit,
      fingerprintKey: ensureFingerprintKey(paths.root, warn),
      retentionDays: config.audit.retentionDays,
      mask: config.audit.mask,
      warn,
    });
    this.#fpKey = this.#audit;

    // A key that cannot round-trip must be discovered at activation, not on the
    // first request: a gateway that masks and then cannot restore is worse than
    // one that refuses to start.
    if (!this.#probeKey()) {
      warn('vault self-test failed; session mappings may not be recoverable after a restart');
    }
    this.#pruneVaults();
  }

  /** @returns the normalized config. */
  get config() {
    return this.#config;
  }

  /** @returns the resolved paths. */
  get paths() {
    return this.#paths;
  }

  /** @returns the audit log, for the tools and the settings page. */
  get audit() {
    return this.#audit;
  }

  /** Encrypt/decrypt a throwaway payload to prove the key and medium work. */
  #probeKey() {
    const probe = new Vault({ sessionId: 'self-test', file: '', key: this.#encKey, degraded: false, warn: this.#warn });
    return probe.selfTest();
  }

  /** Remove session vaults past their time-to-live. */
  #pruneVaults() {
    if (!(this.#vaultTtlHours > 0)) return;
    const cutoff = Date.now() - this.#vaultTtlHours * 60 * 60 * 1000;
    try {
      for (const name of readdirSync(this.#paths.sessions)) {
        if (!name.endsWith('.vault')) continue;
        const file = join(this.#paths.sessions, name);
        try {
          if (statSync(file).mtimeMs < cutoff) rmSync(file, { force: true });
        } catch {
          /* a file that vanished is already gone */
        }
      }
    } catch {
      /* an unreadable directory is reported by the first write instead */
    }
  }

  /**
   * Whether this request may be masked, and under which policy.
   * @param options - the request handed to the waterfall.
   * @returns the decision.
   */
  #decide(options) {
    const sessionId = typeof options?.sessionId === 'string' ? options.sessionId : 'unscoped';
    if (this.#disposed) return { skip: 'disposed', sessionId };
    if (Date.now() < this.#pausedUntil) return { skip: 'paused', sessionId };
    if (this.#config.mode === 'off') return { skip: 'off', sessionId };
    if (!Array.isArray(options?.messages) || options.messages.length === 0) return { skip: 'empty', sessionId };

    const cwd = this.#cwdOf(sessionId);
    const policy = resolveWorkspacePolicy(this.#config, cwd);
    if (policy.mode === 'off') return { skip: 'bypass', policy, sessionId };
    return { skip: '', policy, sessionId };
  }

  /**
   * The working directory of one session, when the session is live.
   * @param sessionId - session id from the request.
   */
  #cwdOf(sessionId) {
    try {
      const session = this.#ctx.get('sessions')?.get?.(sessionId);
      const cwd = session?.header?.cwd;
      return typeof cwd === 'string' ? cwd : '';
    } catch {
      return '';
    }
  }

  /**
   * The detector for one policy, cached by its exact configuration.
   * @param policy - resolved workspace policy.
   */
  #detectorFor(policy) {
    const dictionary = policy.dictionary ?? [];
    const allowValues = policy.allowlist?.values ?? [];
    const allowPatterns = (policy.allowlist?.patterns ?? []).map((entry) => entry.source);
    const key = JSON.stringify([
      this.#config.categories,
      policy.categories,
      dictionary,
      allowValues,
      allowPatterns,
      this.#config.minCustomLength,
      this.#config.nameStrict,
    ]);
    const cached = this.#detectors.get(key);
    if (cached !== undefined) return cached;
    const detector = createDetector({
      categories: policy.categories,
      dictionary,
      allowlist: allowValues,
      allowPatterns,
      minCustomLength: this.#config.minCustomLength,
      nameStrict: this.#config.nameStrict,
    });
    if (this.#detectors.size > 32) this.#detectors.clear();
    this.#detectors.set(key, detector);
    return detector;
  }

  /**
   * The vault for one session, opened on first use.
   * @param sessionId - session id, or `unscoped`.
   */
  #vaultFor(sessionId) {
    const existing = this.#vaults.get(sessionId);
    if (existing !== undefined) return existing;
    if (this.#vaults.size >= MAX_SESSIONS) {
      // Evict the least recently used vault; its file stays on disk and reopens
      // if that session speaks again.
      const oldest = this.#vaults.keys().next().value;
      if (oldest !== undefined) {
        this.#vaults.get(oldest)?.dispose();
        this.#vaults.delete(oldest);
      }
    }
    const vault = Vault.open({
      dir: this.#paths.root,
      sessionId,
      key: this.#encKey,
      degraded: false,
      warn: this.#warn,
    });
    vault.setDelimiters(this.#config.placeholder);
    this.#vaults.set(sessionId, vault);
    // Seed the dedupe set from the mapping restored from disk, so a restart does
    // not re-log values whose audit rows already exist.
    this.#seenPlaceholders.set(
      sessionId,
      new Set(vault.entries().map((entry) => vault.formatPlaceholder(entry.category, entry.index))),
    );
    return vault;
  }

  /** Remember one placeholder as already audited for this session. */
  #markSeen(sessionId, placeholder) {
    let seen = this.#seenPlaceholders.get(sessionId);
    if (seen === undefined) {
      seen = new Set();
      if (this.#seenPlaceholders.size > MAX_SESSIONS) this.#seenPlaceholders.clear();
      this.#seenPlaceholders.set(sessionId, seen);
    }
    seen.add(placeholder);
  }

  /** A memory-only vault used to render placeholders for audit-only detection. */
  #previewVault(sessionId) {
    const vault = Vault.open({ dir: '', sessionId: `audit-${sessionId}`, key: Buffer.alloc(32), degraded: true });
    vault.setDelimiters(this.#config.placeholder);
    return vault;
  }

  /**
   * The `llm/stream` listener body.
   * @param options - the full request.
   * @param next - the downstream chain.
   * @returns the chunk stream.
   */
  handleStream(options, next) {
    if (this.#guard.has(options)) {
      // Second pass: this is the re-dispatched masked request already.
      return next();
    }
    let decision;
    try {
      decision = this.#decide(options);
    } catch (error) {
      this.#warn(`redaction decision failed: ${describe(error)}`);
      return this.#fail(options, next, error);
    }
    if (decision.skip !== '') {
      // A paused gateway is worth one audit line per minute; a bypassed
      // workspace is out of scope by policy and is not logged at all.
      if (decision.skip === 'paused') this.#noteSkip(decision, options);
      return next();
    }
    return this.#maskedStream(options, next, decision);
  }

  /**
   * Mask one request and stream the rehydrated response.
   * @param options - the frozen request.
   * @param next - the downstream chain.
   * @param decision - the resolved policy.
   */
  async *#maskedStream(options, next, decision) {
    const startedAt = Date.now();
    let vault;
    let redacted;
    try {
      const enforcing = decision.policy.mode !== 'audit';
      // In audit mode nothing is substituted, so the real session mapping must
      // not grow: a throwaway vault keeps the record readable and the mapping
      // honest.
      vault = enforcing ? this.#vaultFor(decision.sessionId) : this.#previewVault(decision.sessionId);
      const detector = this.#detectorFor(decision.policy);
      const redactor = createRedactor({
        detector,
        vault,
        policy: decision.policy,
        config: this.#config,
      });
      redacted = redactor.redactMessages(options.messages);
      this.#recordHits(redactor, options, decision, startedAt);
      for (const leftover of redactor.residual()) {
        this.#warn(`residual ${leftover.category} text survived masking (rule ${leftover.ruleId})`);
      }
    } catch (error) {
      this.#warn(`redaction failed: ${describe(error)}`);
      yield* this.#failIterable(options, next, error);
      return;
    }

    // Audit-only mode inspects and records but lets the original through.
    if (decision.policy.mode === 'audit' || !redacted.changed) {
      yield* next();
      return;
    }

    // The mapping must be durable before the request leaves, or the response
    // cannot be restored after a crash.
    if (!vault.flush(true)) {
      this.#warn('session mapping could not be persisted; refusing to send a masked request whose response may be unrecoverable');
      yield* this.#failIterable(options, next, new Error('session mapping is not durable'));
      return;
    }

    const rehydrators = new Map();
    let prepared;
    try {
      prepared = await this.#ctx.llm.prepareCall(this.#callConfig(options), options.signal);
    } catch (error) {
      this.#warn(`model call could not be prepared for the masked request: ${describe(error)}`);
      yield* this.#failIterable(options, next, error);
      return;
    }

    const maskedOptions = {
      ...options,
      ...this.#controlFields(prepared.config),
      messages: redacted.messages,
    };
    this.#guard.add(maskedOptions);
    this.#depth += 1;
    try {
      const stream = prepared.stream(maskedOptions);
      try {
        for await (const chunk of stream) {
          yield* this.#rehydrateChunk(chunk, rehydrators, vault);
        }
      } catch (error) {
        // A provider failure surfaces as the stream protocol's terminal chunk so
        // the turn reports one clear failure instead of an unhandled throw.
        yield {
          type: 'finish',
          reason: options.signal?.aborted
            ? { kind: 'aborted', failure: { code: 'ABORTED', message: 'request aborted' } }
            : { kind: 'error', failure: { code: 'PROVIDER_FAILED', message: describe(error) } },
        };
        return;
      }
      // Release anything still held when the adapter ended without block-end.
      for (const [index, state] of rehydrators) {
        const tail = state.rehydrator.flush();
        if (tail.length > 0) {
          yield {
            type: state.kind === 'reasoning' ? 'reasoning-delta' : 'text-delta',
            index,
            text: tail,
          };
        }
      }
      rehydrators.clear();
    } finally {
      this.#depth -= 1;
      if (this.#depth === 0) this.#guard = new WeakSet();
    }
  }

  /**
   * Rehydrate one chunk, holding partial placeholders across deltas.
   * @param chunk - adapter chunk.
   * @param rehydrators - per-block-index rehydrator state.
   * @param kinds - per-block-index block kind.
   * @param vault - the session vault.
   */
  *#rehydrateChunk(chunk, rehydrators, vault) {
    if (typeof chunk !== 'object' || chunk === null) return;
    const open = this.#config.placeholder.open;
    const close = this.#config.placeholder.close;
    const resolve = (category, index) => {
      const canonical = vault.formatPlaceholder(category.toLowerCase(), index);
      const value = vault.resolve(canonical);
      return value;
    };

    switch (chunk.type) {
      case 'text-delta':
      case 'reasoning-delta': {
        const kind = chunk.type === 'text-delta' ? 'text' : 'reasoning';
        let state = rehydrators.get(chunk.index);
        if (state === undefined) {
          state = {
            kind,
            rehydrator: new Rehydrator({
              resolve,
              open,
              close,
              enabled: this.#config.streamRehydrate,
            }),
          };
          rehydrators.set(chunk.index, state);
        }
        const text = state.rehydrator.push(chunk.text);
        if (text.length > 0) yield { ...chunk, text };
        return;
      }
      case 'block-end': {
        const state = rehydrators.get(chunk.index);
        if (state !== undefined) {
          const tail = state.rehydrator.flush();
          if (tail.length > 0) {
            yield {
              type: chunk.block?.type === 'reasoning' ? 'reasoning-delta' : 'text-delta',
              index: chunk.index,
              text: tail,
            };
          }
          rehydrators.delete(chunk.index);
        }
        const block = this.#rehydrateBlock(chunk.block, vault, open, close);
        yield block === chunk.block ? chunk : { ...chunk, block };
        return;
      }
      case 'finish': {
        for (const [index, state] of rehydrators) {
          const tail = state.rehydrator.flush();
          if (tail.length > 0) {
            yield {
              type: state.kind === 'reasoning' ? 'reasoning-delta' : 'text-delta',
              index,
              text: tail,
            };
          }
        }
        rehydrators.clear();
        yield chunk;
        return;
      }
      default:
        yield chunk;
    }
  }

  /**
   * Rehydrate the authoritative content of one finished block.
   * @param block - the block carried by `block-end`.
   * @param vault - session vault.
   * @param open - opening delimiter.
   * @param close - closing delimiter.
   */
  #rehydrateBlock(block, vault, open, close) {
    if (typeof block !== 'object' || block === null) return block;
    const resolve = (category, index) => vault.resolve(vault.formatPlaceholder(category.toLowerCase(), index));
    if ((block.type === 'text' || block.type === 'reasoning') && typeof block.text === 'string') {
      const restored = rehydrateText(block.text, resolve, open, close);
      return restored.text === block.text ? block : { ...block, text: restored.text };
    }
    if (block.type === 'tool-call' && typeof block.arguments === 'string') {
      const restored = rehydrateArguments(block.arguments, resolve, open, close);
      return restored === block.arguments ? block : { ...block, arguments: restored };
    }
    return block;
  }

  /**
   * Record one request's masks in the audit trail.
   * @param redactor - the request's redactor.
   * @param options - the request.
   * @param decision - the resolved policy.
   * @param startedAt - request start.
   */
  #recordHits(redactor, options, decision, startedAt) {
    const hits = redactor.hits();
    const enforce = decision.policy.mode !== 'audit';
    const workspaceFp = this.#audit.workspaceFingerprint(decision.policy.cwd ?? '');
    let masked = 0;
    const byCategory = {};
    const session = this.#sessionStats(decision.sessionId);
    session.requests += 1;
    session.lastAt = startedAt;

    for (const hit of hits) {
      // With dedupe on, the trail records a value once per session; the
      // occurrence count on that one row keeps the volume honest.
      const isNew = hit.created === true || this.#seenPlaceholders.get(decision.sessionId)?.has(hit.placeholder) !== true;
      if (this.#config.audit.dedupe && !isNew) continue;
      this.#audit.record({
        timestamp: startedAt,
        sessionId: decision.sessionId,
        workspaceFp,
        provider: options.provider ?? '',
        model: options.model ?? '',
        purpose: options.purpose ?? '',
        direction: 'request',
        action: enforce ? 'redact' : 'observe',
        category: hit.category,
        ruleId: hit.ruleId,
        placeholder: hit.placeholder,
        mask: maskValue(hit.value, hit.category),
        valueFp: this.#audit.fingerprint(hit.value),
        valueShape: hit.shape ?? '',
        validation: hit.validation ?? 'none',
        count: hit.count,
        outcome: enforce ? 'masked' : 'observed',
      });
      byCategory[hit.category] = (byCategory[hit.category] ?? 0) + hit.count;
      if (enforce) {
        masked += hit.count;
        session.placeholders += hit.count;
        session.byCategory[hit.category] = (session.byCategory[hit.category] ?? 0) + hit.count;
        this.#lastMask.push({
          ts: startedAt,
          category: hit.category,
          mask: maskValue(hit.value, hit.category),
          placeholder: hit.placeholder,
          sessionId: decision.sessionId,
          direction: 'request',
        });
      }
    }
    for (const hit of hits) this.#markSeen(decision.sessionId, hit.placeholder);
    if (this.#lastMask.length > 40) this.#lastMask = this.#lastMask.slice(-40);

    this.#audit.observe({ placeholders: masked, byCategory });
    this.#audit.persistStats();
  }

  /**
   * Record a request that was let through unmasked by policy.
   * @param decision - the resolved policy.
   * @param options - the request.
   */
  #noteSkip(decision, options) {
    const sessionId = decision.sessionId ?? 'unscoped';
    const policy = decision.policy ?? resolveWorkspacePolicy(this.#config, this.#cwdOf(sessionId));
    const bucket = `${sessionId}\u0000${decision.skip}`;
    const session = this.#sessionStats(sessionId);
    session.requests += 1;
    session.lastAt = Date.now();
    // A paused session issues many requests per minute; one audit line per
    // minute per session and reason is enough evidence without the noise.
    if (Date.now() - (this.#skipNoted.get(bucket) ?? 0) < 60_000) return;
    this.#skipNoted.set(bucket, Date.now());
    if (this.#skipNoted.size > 256) this.#skipNoted.clear();
    this.#audit.record({
      sessionId,
      workspaceFp: this.#audit.workspaceFingerprint(policy.cwd ?? ''),
      provider: options?.provider ?? '',
      model: options?.model ?? '',
      direction: 'request',
      action: 'pause-skip',
      category: '',
      ruleId: decision.skip,
      outcome: 'allowed',
    });
  }

  /** Fetch or create one session's counters. */
  #sessionStats(sessionId) {
    let stats = this.#sessions.get(sessionId);
    if (stats === undefined) {
      stats = { requests: 0, placeholders: 0, byCategory: {}, lastAt: 0 };
      if (this.#sessions.size > MAX_SESSIONS) this.#sessions.clear();
      this.#sessions.set(sessionId, stats);
    }
    return stats;
  }

  /**
   * The six fields a prepared call compares, taken from the current request.
   * @param options - the request.
   */
  #callConfig(options) {
    const config = { provider: options.provider, model: options.model };
    if (options.reasoningEffort !== undefined) config.reasoningEffort = options.reasoningEffort;
    if (options.temperature !== undefined) config.temperature = options.temperature;
    if (options.maxTokens !== undefined) config.maxTokens = options.maxTokens;
    if (options.stop !== undefined) config.stop = options.stop;
    return config;
  }

  /**
   * The resolved control fields, so the re-dispatched request matches the
   * prepared call's resolved config exactly.
   * @param resolved - `prepared.config`.
   */
  #controlFields(resolved) {
    const fields = {};
    for (const key of ['reasoningEffort', 'temperature', 'maxTokens', 'stop']) {
      if (resolved?.[key] !== undefined) fields[key] = resolved[key];
      else delete fields[key];
    }
    return fields;
  }

  /** Fail closed (or pass, when configured) for one request. */
  #fail(options, next, error) {
    if (this.#config.onError === 'pass') {
      this.#warn(`redaction failed and onError=pass, sending the original request: ${describe(error)}`);
      return next();
    }
    this.#audit.observe({ blocked: 1 });
    this.#audit.persistStats();
    this.#audit.record({
      sessionId: typeof options?.sessionId === 'string' ? options.sessionId : '',
      provider: options?.provider ?? '',
      model: options?.model ?? '',
      direction: 'request',
      action: 'block',
      category: '',
      ruleId: 'onerror',
      outcome: 'blocked',
    });
    return blockedStream();
  }

  /** Fail inside a generator, where `yield` is available. */
  async *#failIterable(options, next, error) {
    if (this.#config.onError === 'pass') {
      this.#warn(`redaction failed and onError=pass, sending the original request: ${describe(error)}`);
      yield* next();
      return;
    }
    this.#audit.observe({ blocked: 1 });
    this.#audit.persistStats();
    this.#audit.record({
      sessionId: typeof options?.sessionId === 'string' ? options.sessionId : '',
      provider: options?.provider ?? '',
      model: options?.model ?? '',
      direction: 'request',
      action: 'block',
      category: '',
      ruleId: 'onerror',
      outcome: 'blocked',
    });
    yield {
      type: 'finish',
      reason: {
        kind: 'error',
        failure: {
          code: FAILURE_CODE,
          message:
            '出网脱敏网关无法完成脱敏，已阻止本次请求（未发送原文）。请查看 DSH 日志或把 onError 设为 pass。',
        },
      },
    };
  }

  /** Pause protection for a number of milliseconds. */
  pause(durationMs) {
    const horizon = Date.now() + Math.max(0, durationMs);
    this.#pausedUntil = horizon;
    return this.state().pausedUntil;
  }

  /** Resume protection immediately. */
  resume() {
    this.#pausedUntil = 0;
  }

  /**
   * Apply a runtime configuration change.
   * @param patch - partial config from the settings page.
   * @returns the applied fields and whether they will survive a restart.
   */
  applyConfig(patch) {
    const applied = [];
    const source = typeof patch === 'object' && patch !== null ? patch : {};
    const next = { ...this.#config };
    if (typeof source.mode === 'string' && ['enforce', 'audit', 'off'].includes(source.mode)) {
      next.mode = source.mode;
      applied.push('mode');
    }
    if (typeof source.categories === 'object' && source.categories !== null) {
      const categories = { ...this.#config.categories };
      for (const [category, enabled] of Object.entries(source.categories)) {
        if (Object.hasOwn(categories, category) && typeof enabled === 'boolean') {
          categories[category] = enabled;
        }
      }
      next.categories = Object.freeze(categories);
      applied.push('categories');
      this.#detectors.clear();
    }
    if (Array.isArray(source.dictionary)) {
      next.dictionary = Object.freeze(
        source.dictionary.filter((entry) => typeof entry === 'string' && entry.trim().length > 0),
      );
      applied.push('dictionary');
      this.#detectors.clear();
    }
    if (typeof source.onError === 'string' && ['block', 'pass'].includes(source.onError)) {
      next.onError = source.onError;
      applied.push('onError');
    }
    this.#config = Object.freeze(next);
    if (applied.length > 0) this.#persistSoon(source, applied);
    return { applied, persisted: this.#canPersist() };
  }

  /** Whether this profile exposes a config editor for the plugin row. */
  #canPersist() {
    try {
      return this.#ctx.get('configEditor') !== undefined && this.#ctx.fiber?.entry !== undefined;
    } catch {
      return false;
    }
  }

  /**
   * Persist a change into the profile's row config after the response settles.
   *
   * Editing an ordinary field restarts the plugin, so the write is deferred and
   * failures are reported instead of silently diverging from what the user sees.
   * @param patch - the change to merge into the row config.
   * @param fields - the field names being persisted.
   */
  #persistSoon(patch, fields) {
    if (!this.#canPersist()) return;
    this.#pendingPatch = { ...this.#pendingPatch };
    for (const field of fields) {
      if (patch[field] !== undefined) this.#pendingPatch[field] = patch[field];
    }
    if (this.#persistTimer !== undefined) return;
    this.#persistTimer = setTimeout(() => {
      this.#persistTimer = undefined;
      const pending = this.#pendingPatch;
      this.#pendingPatch = {};
      void this.#persistNow(pending);
    }, 300);
    if (typeof this.#persistTimer?.unref === 'function') this.#persistTimer.unref();
  }

  /** Write the pending patch through the config editor. */
  async #persistNow(patch) {
    try {
      const entry = this.#ctx.fiber?.entry;
      const editor = this.#ctx.get('configEditor');
      if (entry === undefined || editor === undefined) return;
      await editor.edit(entry, (current) => ({ ...current, ...patch }));
    } catch (error) {
      this.#warn(`runtime change could not be written to the profile config: ${describe(error)}`);
    }
  }

  /** @returns the state surface rendered by the settings page. */
  state() {
    const now = Date.now();
    const total = [...this.#sessions.values()].reduce(
      (accumulator, session) => ({
        requests: accumulator.requests + session.requests,
        placeholders: accumulator.placeholders + session.placeholders,
        byCategory: mergeCounts(accumulator.byCategory, session.byCategory),
      }),
      { requests: 0, placeholders: 0, byCategory: {} },
    );
    const activeSessionId = this.#mostRecentSession(now);
    const active = activeSessionId === '' ? { requests: 0, placeholders: 0, byCategory: {} } : this.#sessions.get(activeSessionId);
    const cwd = activeSessionId === '' ? '' : this.#cwdOf(activeSessionId);
    const policy = resolveWorkspacePolicy(this.#config, cwd);
    const auditStats = this.#audit.stats();
    return {
      version: '1.0.0',
      mode: this.#config.mode,
      paused: now < this.#pausedUntil,
      pausedUntil: this.#pausedUntil,
      onError: this.#config.onError,
      categories: { ...policy.categories },
      workspace: { path: cwd, policy: policy.mode, matched: policy.matched, note: policy.note ?? '' },
      workspaces: this.#config.workspaces.map((workspace) => ({
        path: workspace.path,
        policy: workspace.policy,
        note: workspace.note,
        active: policy.matched !== '' && policy.matched === workspace.path,
      })),
      session: {
        id: activeSessionId,
        requests: active?.requests ?? 0,
        placeholders: active?.placeholders ?? 0,
        byCategory: active?.byCategory ?? {},
      },
      totals: {
        requests: auditStats.requests,
        placeholders: auditStats.placeholders,
        blocked: auditStats.blocked,
        lastAt: auditStats.lastAt,
        byCategory: auditStats.byCategory,
        liveRequests: total.requests,
        livePlaceholders: total.placeholders,
      },
      recent: this.#lastMask.slice(-20).reverse(),
      paths: {
        dataDir: this.#paths.root,
        auditDir: this.#paths.audit,
        vaultDir: this.#paths.sessions,
        keySource: process.env.DSH_REDACT_KEY === undefined ? 'local key file' : 'DSH_REDACT_KEY',
        keyFile: `${this.#paths.root}/master.key`,
      },
      chain: { head: auditStats.head },
      config: {
        placeholder: this.#config.placeholder,
        promptHint: this.#config.promptHint,
        streamRehydrate: this.#config.streamRehydrate,
        retentionDays: this.#config.audit.retentionDays,
        dictionary: [...this.#config.dictionary],
        allowlist: {
          values: [...this.#config.allowlist.values],
          patterns: this.#config.allowlist.patterns.map((entry) => entry.source),
        },
      },
    };
  }

  /** The session with the most recent activity, or an empty string. */
  #mostRecentSession() {
    let best = '';
    let bestAt = -1;
    for (const [sessionId, stats] of this.#sessions) {
      if (stats.lastAt > bestAt) {
        best = sessionId;
        bestAt = stats.lastAt;
      }
    }
    return best;
  }

  /** @returns the audit log's own fingerprint of one value, for tooling. */
  fingerprint(value) {
    return this.#fpKey.fingerprint(value);
  }

  /** Flush every session mapping and drop decrypted material. */
  dispose() {
    this.#disposed = true;
    if (this.#persistTimer !== undefined) {
      clearTimeout(this.#persistTimer);
      this.#persistTimer = undefined;
    }
    for (const vault of this.#vaults.values()) vault.dispose();
    this.#vaults.clear();
    this.#audit.persistStats();
  }
}

/** Merge two category count maps. */
function mergeCounts(left, right) {
  const out = { ...left };
  for (const [category, count] of Object.entries(right)) out[category] = (out[category] ?? 0) + count;
  return out;
}

/** Rehydrate a JSON tool-argument payload. */
function rehydrateArguments(text, resolve, open, close) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return rehydrateText(text, resolve, open, close).text;
  }
  const walk = (value) => {
    if (typeof value === 'string') return rehydrateText(value, resolve, open, close).text;
    if (Array.isArray(value)) return value.map(walk);
    if (typeof value === 'object' && value !== null) {
      const out = {};
      for (const [key, entry] of Object.entries(value)) out[key] = walk(entry);
      return out;
    }
    return value;
  };
  const next = walk(parsed);
  return next === parsed ? text : JSON.stringify(next);
}

/** A stream that only reports the failure, used where `yield` is unavailable. */
function blockedStream() {
  return (async function* blocked() {
    yield {
      type: 'finish',
      reason: {
        kind: 'error',
        failure: {
          code: FAILURE_CODE,
          message: '出网脱敏网关无法完成脱敏，已阻止本次请求（未发送原文）。',
        },
      },
    };
  })();
}
