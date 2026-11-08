/**
 * Request redaction: the outbound half of the gateway.
 *
 * Everything here is pure with respect to its inputs — the request objects the
 * agent loop hands the `llm/stream` waterfall are frozen, so redaction always
 * builds new messages and never writes through to the immutable originals. That
 * is what keeps the durable session log (and therefore what the user reads)
 * in its original form while the wire copy carries placeholders.
 *
 * @module dsh-redact-gateway/redact
 */

/** Text-bearing content block types. Image and file blocks are references only. */
const TEXT_BLOCKS = new Set(['text', 'reasoning']);

/**
 * Aggregate per-request mask counts, keyed by category and value.
 */
class HitTally {
  #byKey = new Map();

  /**
   * Record one occurrence.
   * @param category - detector category.
   * @param ruleId - the rule that claimed the span.
   * @param value - original text.
   * @param placeholder - replacement text.
   * @param validation - how the rule validated this shape.
   * @param shape - the concrete shape the rule recognised.
   * @param created - whether this call minted the placeholder.
   */
  add(category, ruleId, value, placeholder, validation, shape, created) {
    const key = `${category}\u0000${value}`;
    const existing = this.#byKey.get(key);
    if (existing !== undefined) {
      existing.count += 1;
      existing.created = existing.created || created;
      return;
    }
    this.#byKey.set(key, { category, ruleId, value, placeholder, validation, shape, created, count: 1 });
  }

  /** @returns the tallied hits as a plain array. */
  list() {
    return [...this.#byKey.values()];
  }

  /** @returns how many distinct values were masked. */
  get size() {
    return this.#byKey.size;
  }
}

/**
 * Build the redaction engine for one request.
 *
 * @param options.detector - `{ detect(text) }` from `lib/rules.js`.
 * @param options.vault - the session vault that mints placeholders.
 * @param options.policy - resolved workspace policy (`categories`, `dictionary`, …).
 * @param options.config - normalized plugin config (placeholder delimiters, limits).
 * @param options.verifyResidual - re-scan redacted text for survivors.
 */
export function createRedactor({ detector, vault, policy, config, verifyResidual = true }) {
  const tally = new HitTally();
  const residual = [];
  const open = config.placeholder.open;
  const close = config.placeholder.close;

  /**
   * Mask every detected span in one string.
   * @param text - candidate text.
   * @returns the redacted text.
   */
  function redactText(text) {
    if (typeof text !== 'string' || text.length === 0) return text;
    const detections = detector.detect(text);
    if (detections.length === 0) return text;

    let out = '';
    let cursor = 0;
    for (const hit of detections) {
      // Defensive: a detector that returns an out-of-order or overlapping span
      // must never corrupt the text, so anything behind the cursor is skipped.
      if (hit.start < cursor || hit.end > text.length || hit.end <= hit.start) continue;
      const { placeholder, created } = vault.placeholder(hit.category, hit.value);
      out += text.slice(cursor, hit.start);
      out += placeholder;
      cursor = hit.end;
      tally.add(
        hit.category,
        hit.ruleId,
        hit.value,
        placeholder,
        hit.validation ?? 'none',
        hit.shape ?? '',
        created,
      );
    }
    out += text.slice(cursor);

    if (verifyResidual && out.length <= 64 * 1024) {
      for (const leftover of detector.detect(out)) {
        residual.push({ category: leftover.category, ruleId: leftover.ruleId });
      }
    }
    return out;
  }

  /**
   * Mask every string leaf of a JSON value, preserving structure.
   * @param value - parsed JSON.
   * @returns the masked copy.
   */
  function redactJsonValue(value) {
    if (typeof value === 'string') return redactText(value);
    if (Array.isArray(value)) {
      let changed = false;
      const next = value.map((entry) => {
        const masked = redactJsonValue(entry);
        if (masked !== entry) changed = true;
        return masked;
      });
      return changed ? next : value;
    }
    if (typeof value === 'object' && value !== null) {
      let changed = false;
      const next = {};
      for (const [key, entry] of Object.entries(value)) {
        const masked = redactJsonValue(entry);
        if (masked !== entry) changed = true;
        next[key] = masked;
        const maskedKey = redactText(key);
        if (maskedKey !== key) changed = true;
        if (maskedKey !== key) {
          delete next[key];
          next[maskedKey] = masked;
        }
      }
      return changed ? next : value;
    }
    return value;
  }

  /**
   * Mask one tool-call argument payload.
   *
   * The payload is JSON text on the wire. Parsing first keeps the replacement
   * inside string boundaries — a masked email can never break the quoting the
   * way a raw text substitution could.
   * @param text - the arguments string.
   */
  function redactArguments(text) {
    if (typeof text !== 'string' || text.length === 0) return text;
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return redactText(text);
    }
    const masked = redactJsonValue(parsed);
    if (masked === parsed) return text;
    try {
      return JSON.stringify(masked);
    } catch {
      return redactText(text);
    }
  }

  /**
   * Mask every block of one content array.
   * @param content - message content blocks.
   * @returns the masked array, or the original when nothing changed.
   */
  function redactContent(content) {
    if (!Array.isArray(content)) return content;
    let changed = false;
    const next = content.map((block) => {
      if (typeof block !== 'object' || block === null) return block;
      if (TEXT_BLOCKS.has(block.type) && typeof block.text === 'string') {
        const masked = redactText(block.text);
        if (masked === block.text) return block;
        changed = true;
        return { ...block, text: masked };
      }
      if (block.type === 'tool-call' && typeof block.arguments === 'string') {
        const masked = redactArguments(block.arguments);
        if (masked === block.arguments) return block;
        changed = true;
        return { ...block, arguments: masked };
      }
      return block;
    });
    return changed ? next : content;
  }

  /**
   * Mask a whole request message list.
   * @param messages - the frozen request messages.
   * @returns the masked list (the original when nothing changed) and a flag.
   */
  function redactMessages(messages) {
    if (!Array.isArray(messages)) return { messages, changed: false };
    let changed = false;
    const next = messages.map((message) => {
      if (typeof message !== 'object' || message === null) return message;
      const content = redactContent(message.content);
      if (content === message.content) return message;
      changed = true;
      return { ...message, content };
    });
    return { messages: changed ? next : messages, changed };
  }

  return {
    redactText,
    redactMessages,
    redactArguments,
    redactJsonValue,
    /** @returns per-request tallied masks. */
    hits() {
      return tally.list();
    },
    /** @returns categories and rules that survived redaction, for the audit trail. */
    residual() {
      return residual;
    },
    /** @returns whether this request masked anything. */
    get touched() {
      return tally.size > 0;
    },
  };
}

/**
 * Apply a text transform to every text-bearing block of a committed message.
 * Used on the inbound path where the structure is already final.
 * @param content - content blocks.
 * @param transform - per-string transform.
 * @returns the transformed blocks, or the original array when nothing changed.
 */
export function mapTextBlocks(content, transform) {
  if (!Array.isArray(content)) return { content, changed: false };
  let changed = false;
  const next = content.map((block) => {
    if (typeof block !== 'object' || block === null) return block;
    if (TEXT_BLOCKS.has(block.type) && typeof block.text === 'string') {
      const replaced = transform(block.text);
      if (replaced === block.text) return block;
      changed = true;
      return { ...block, text: replaced };
    }
    return block;
  });
  return { content: changed ? next : content, changed };
}
