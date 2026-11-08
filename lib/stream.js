/**
 * Streaming placeholder rehydration.
 *
 * A response arrives as token-level deltas, and a placeholder such as
 * `[EMAIL_1]` straddles delta boundaries all the time. Emitting each delta
 * unchanged would therefore leak an unreplaced `[EMA` into the transcript, so
 * this module holds back a trailing run that could still become a placeholder
 * and releases it as soon as the text can no longer complete one.
 *
 * Two measured realities shape the parser (arXiv:2610.34012):
 * - models rewrite the delimiters — `<Name_1>` becomes `[Name_1]`, `[A_1]`
 *   becomes `[[A_1]]`, `[ A_1 ]` gains spaces — so matching is deliberately
 *   tolerant of bracket style, width, and separators,
 * - models also *invent* placeholders that were never issued, so a
 *   placeholder-shaped token that does not resolve is passed through untouched
 *   and counted, never guessed at.
 *
 * @module dsh-redact-gateway/stream
 */

/** Opening delimiters accepted while rehydrating, including full-width forms. */
const OPEN = '\\[［【(（{｛';
/** Closing delimiters accepted while rehydrating, including full-width forms. */
const CLOSE = '\\]］】)）}｝';
/** Longest trailing run worth holding while waiting for the next delta. */
const MAX_HOLD = 48;

/**
 * Build the tolerant placeholder matcher for one token grammar.
 * @param open - configured opening delimiter (kept for documentation symmetry).
 * @param close - configured closing delimiter (kept for documentation symmetry).
 * @returns a global regular expression capturing category and index.
 */
function placeholderPattern(open, close) {
  // The delimiters above are always accepted; the configured pair is folded in
  // by escaping it, so a custom `{{ }}` installation still parses its own form.
  const extraOpen = escapeClass(open);
  const extraClose = escapeClass(close);
  return new RegExp(
    `[${OPEN}${extraOpen}]{1,2}\\s*([A-Za-z]{1,20})\\s*[_\\-\\s]?\\s*(\\d{1,6})\\s*[${CLOSE}${extraClose}]{1,2}`,
    'g',
  );
}

/** Escape text for use inside a character class. */
function escapeClass(text) {
  return text.replace(/[\\\]^[-]/g, '\\$&');
}

/**
 * The shape a trailing fragment must have to be worth holding: an opening
 * delimiter followed only by characters a placeholder can still grow into.
 */
const PARTIAL = new RegExp(
  `[${OPEN}${CLOSE}]*[${OPEN}][^${CLOSE}]{0,${MAX_HOLD}}$|^[A-Za-z]{0,20}[_\\-\\s]?\\d{0,6}$`,
);

/**
 * Rehydrate one text stream incrementally.
 */
export class Rehydrator {
  #resolve;
  #pattern;
  #canonical;
  #buffer = '';
  #held = 0;
  #replaced = 0;
  #unknown = 0;
  #repairs = 0;
  #enabled;

  /**
   * @param options.resolve - maps `category`/`index` to the original value.
   * @param options.open - configured opening delimiter.
   * @param options.close - configured closing delimiter.
   * @param options.enabled - when false, every delta passes through untouched.
   */
  constructor({ resolve, open = '[', close = ']', enabled = true }) {
    this.#resolve = resolve;
    this.#pattern = placeholderPattern(open, close);
    this.#canonical = (category, index) => `${open}${category}_${index}${close}`;
    this.#enabled = enabled;
  }

  /** @returns how many placeholders this stream has restored. */
  get replaced() {
    return this.#replaced;
  }

  /** @returns how many placeholder-shaped tokens resolved to nothing. */
  get unknown() {
    return this.#unknown;
  }

  /** @returns how many places a tolerant parse rescued a mangled token. */
  get repairs() {
    return this.#repairs;
  }

  /**
   * Feed one delta and receive the text that is safe to publish now.
   * @param text - delta text.
   * @returns the publishable prefix (possibly empty).
   */
  push(text) {
    if (typeof text !== 'string' || text.length === 0) return '';
    if (!this.#enabled) return text;
    this.#buffer += text;
    return this.#drain(false);
  }

  /**
   * Release everything still held, rehydrating a final partial token.
   * @returns the remaining publishable text.
   */
  flush() {
    if (!this.#enabled) {
      const rest = this.#buffer;
      this.#buffer = '';
      return rest;
    }
    return this.#drain(true);
  }

  /**
   * Replace complete placeholders and decide how much trailing text to hold.
   * @param final - release the held tail as well.
   */
  #drain(final) {
    const pattern = new RegExp(this.#pattern.source, this.#pattern.flags);
    let out = '';
    let cursor = 0;
    let match;
    while ((match = pattern.exec(this.#buffer)) !== null) {
      out += this.#buffer.slice(cursor, match.index);
      const category = match[1].toUpperCase();
      const index = Number.parseInt(match[2], 10);
      const value = this.#resolve(category, index);
      if (value === undefined) {
        // An invented or already-consumed token: never guess, publish verbatim
        // and count it so the audit trail can show the residue.
        this.#unknown += 1;
        out += match[0];
      } else {
        this.#replaced += 1;
        if (match[0] !== this.#canonical(category, index)) this.#repairs += 1;
        out += value;
      }
      cursor = match.index + match[0].length;
      pattern.lastIndex = cursor;
    }
    let rest = this.#buffer.slice(cursor);

    if (final) {
      this.#buffer = '';
      return out + rest;
    }
    const hold = this.#holdableLength(rest);
    if (hold > 0) {
      this.#held = hold;
      const tail = rest.slice(rest.length - hold);
      this.#buffer = tail;
      return out + rest.slice(0, rest.length - hold);
    }
    this.#buffer = '';
    return out + rest;
  }

  /**
   * How many trailing characters may still be the beginning of a placeholder.
   *
   * Only an *unterminated* candidate is worth holding; a closed but unresolved
   * token is emitted immediately (`#drain` already counted it).
   * @param text - the text after the last complete match.
   */
  #holdableLength(text) {
    if (text.length === 0) return 0;
    const window = text.slice(-MAX_HOLD);
    const open = window.search(new RegExp(`[${OPEN}]`));
    if (open === -1) return 0;
    const candidate = window.slice(open);
    if (new RegExp(`[${CLOSE}]`).test(candidate)) return 0;
    if (!PARTIAL.test(candidate)) return 0;
    this.#held = candidate.length;
    return candidate.length;
  }
}

/**
 * Repair a completed text in one pass: the same tolerant grammar applied to a
 * whole string, for paths that never stream (tool arguments, stored text).
 * @param text - text to repair.
 * @param resolve - maps category/index to the original value.
 * @param open - configured opening delimiter.
 * @param close - configured closing delimiter.
 * @returns the repaired text and per-call counters.
 */
export function rehydrateText(text, resolve, open = '[', close = ']') {
  const rehydrator = new Rehydrator({ resolve, open, close });
  const head = rehydrator.push(text);
  return {
    text: head + rehydrator.flush(),
    replaced: rehydrator.replaced,
    unknown: rehydrator.unknown,
    repairs: rehydrator.repairs,
  };
}
