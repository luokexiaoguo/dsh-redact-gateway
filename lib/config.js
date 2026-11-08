/**
 * Configuration normalization and per-workspace policy resolution.
 *
 * The Loader hands this plugin whatever the profile's `cordis.patch.yml` row
 * declares, so every field is treated as untrusted input: unknown keys are
 * dropped, wrong types fall back to a documented default, and a malformed
 * workspace entry is skipped with a warning instead of failing the whole plugin
 * (a security product that refuses to boot protects nothing).
 *
 * @module dsh-redact-gateway/config
 */

/** Categories the detector knows about, in placeholder-numbering order. */
export const CATEGORIES = Object.freeze([
  'secret',
  'idcard',
  'bankcard',
  'phone',
  'email',
  'address',
  'name',
  'org',
  'custom',
]);

/** Categories enabled out of the box. `address`, `name` and `org` stay on because
 * a security review expects them, but each carries a documented false-positive
 * risk that a workspace policy can narrow. */
const DEFAULT_CATEGORY_STATE = Object.freeze({
  secret: true,
  idcard: true,
  bankcard: true,
  phone: true,
  email: true,
  address: true,
  name: true,
  org: true,
  custom: true,
});

export const MODES = Object.freeze(['enforce', 'audit', 'off']);
export const POLICIES = Object.freeze(['enforce', 'audit', 'bypass']);
const ERROR_ACTIONS = Object.freeze(['block', 'pass']);

const DEFAULT_AUDIT_RETENTION_DAYS = 90;
// Single square brackets: a benchmark of model round-tripping (arXiv:2610.34012)
// found `[TYPE_1]` survives best — models convert angle brackets to square ones
// themselves, and `[[…]]` collides with wiki-link syntax.
const DEFAULT_PLACEHOLDER_OPEN = '[';
const DEFAULT_PLACEHOLDER_CLOSE = ']';

/**
 * Read one enumerated field.
 * @param value - raw configured value.
 * @param allowed - accepted spellings.
 * @param fallback - value used when the input is not an accepted spelling.
 */
function pickEnum(value, allowed, fallback) {
  return typeof value === 'string' && allowed.includes(value) ? value : fallback;
}

/**
 * Read one boolean field, honoring explicit strings from YAML.
 * @param value - raw configured value.
 * @param fallback - value used when the input is not recognizable.
 */
function pickBoolean(value, fallback) {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return fallback;
}

/**
 * Read one non-negative integer.
 * @param value - raw configured value.
 * @param fallback - value used when the input is not a finite non-negative number.
 * @param max - inclusive upper bound.
 */
function pickInteger(value, fallback, max = Number.MAX_SAFE_INTEGER) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return fallback;
  return Math.min(Math.floor(value), max);
}

/**
 * Read one string list, dropping blanks and duplicates.
 * @param value - raw configured value.
 * @param fallback - value used when the input is not an array.
 */
function pickStringList(value, fallback = []) {
  if (!Array.isArray(value)) return [...fallback];
  const seen = new Set();
  const out = [];
  for (const entry of value) {
    if (typeof entry !== 'string') continue;
    const trimmed = entry.trim();
    if (trimmed.length === 0 || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

/**
 * Read a per-category enable map. Unknown category names are ignored, and a
 * missing category inherits `base`, so a workspace can list only its deltas.
 * @param value - raw configured value.
 * @param base - starting state.
 */
function pickCategories(value, base) {
  const out = { ...base };
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return out;
  for (const category of CATEGORIES) {
    if (!Object.hasOwn(value, category)) continue;
    const entry = value[category];
    if (typeof entry === 'boolean') out[category] = entry;
  }
  return out;
}

/**
 * Compile a configured allow pattern, skipping patterns JavaScript rejects.
 * @param source - regular-expression source text.
 * @param warn - diagnostic sink.
 */
function compilePattern(source, warn) {
  try {
    return new RegExp(source, 'u');
  } catch {
    try {
      return new RegExp(source);
    } catch (error) {
      warn(`allowlist pattern ignored: ${error instanceof Error ? error.message : String(error)}`);
      return undefined;
    }
  }
}

/**
 * Normalize one configured allowlist.
 * @param value - raw `allowlist` object.
 * @param warn - diagnostic sink.
 */
function pickAllowlist(value, warn) {
  const raw = typeof value === 'object' && value !== null ? value : {};
  const patterns = [];
  for (const source of pickStringList(raw.patterns)) {
    const compiled = compilePattern(source, warn);
    if (compiled !== undefined) patterns.push({ source, regex: compiled });
  }
  return { values: pickStringList(raw.values), patterns };
}

/**
 * Resolve one configured workspace policy.
 * @param value - raw workspace entry.
 * @param warn - diagnostic sink.
 * @param inherited - global category state.
 * @returns the normalized entry, or `undefined` when the entry is unusable.
 */
function pickWorkspace(value, warn, inherited) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const path = typeof value.path === 'string' ? value.path.trim() : '';
  if (path.length === 0) {
    warn('workspace entry without a path was ignored');
    return undefined;
  }
  return {
    path,
    policy: pickEnum(value.policy, POLICIES, 'enforce'),
    categories: pickCategories(value.categories, inherited),
    dictionary: pickStringList(value.dictionary),
    allowlist: value.allowlist === undefined ? undefined : pickAllowlist(value.allowlist, warn),
    note: typeof value.note === 'string' ? value.note : '',
  };
}

/**
 * Normalize the plugin's whole config.
 * @param raw - the Loader row's `config` object, of unknown shape.
 * @param warn - diagnostic sink for recoverable problems.
 * @returns a frozen, fully defaulted config.
 */
export function normalizeConfig(raw, warn = () => {}) {
  const source = typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? raw : {};

  const categories = pickCategories(source.categories, DEFAULT_CATEGORY_STATE);

  const placeholderSource =
    typeof source.placeholder === 'object' && source.placeholder !== null ? source.placeholder : {};
  let open = typeof placeholderSource.open === 'string' && placeholderSource.open.length > 0
    ? placeholderSource.open
    : DEFAULT_PLACEHOLDER_OPEN;
  let close = typeof placeholderSource.close === 'string' && placeholderSource.close.length > 0
    ? placeholderSource.close
    : DEFAULT_PLACEHOLDER_CLOSE;
  if (open === close || open.length > 4 || close.length > 4) {
    warn('unsupported placeholder delimiters were replaced by the defaults');
    open = DEFAULT_PLACEHOLDER_OPEN;
    close = DEFAULT_PLACEHOLDER_CLOSE;
  }

  const auditSource = typeof source.audit === 'object' && source.audit !== null ? source.audit : {};

  const workspaces = [];
  if (Array.isArray(source.workspaces)) {
    for (const entry of source.workspaces) {
      const picked = pickWorkspace(entry, warn, categories);
      if (picked !== undefined) workspaces.push(picked);
    }
  }

  const allowlist = pickAllowlist(source.allowlist, warn);

  return Object.freeze({
    mode: pickEnum(source.mode, MODES, 'enforce'),
    onError: pickEnum(source.onError, ERROR_ACTIONS, 'block'),
    categories: Object.freeze(categories),
    dictionary: Object.freeze(pickStringList(source.dictionary)),
    allowlist: Object.freeze(allowlist),
    workspaces: Object.freeze(workspaces),
    placeholder: Object.freeze({ open, close }),
    promptHint: pickBoolean(source.promptHint, true),
    streamRehydrate: pickBoolean(source.streamRehydrate, true),
    nameStrict: pickBoolean(source.nameStrict, true),
    minCustomLength: pickInteger(source.minCustomLength, 2, 16),
    vaultTtlHours: pickInteger(source.vaultTtlHours, 168, 8760),
    audit: Object.freeze({
      retentionDays: pickInteger(auditSource.retentionDays, DEFAULT_AUDIT_RETENTION_DAYS, 3650),
      mask: pickBoolean(auditSource.mask, true),
      // One audit row per distinct value per session: a long conversation
      // re-sends its whole history on every request, so per-occurrence rows turn
      // seventy distinct findings into nearly a thousand identical lines.
      dedupe: pickBoolean(auditSource.dedupe, true),
      dir: typeof auditSource.dir === 'string' ? auditSource.dir.trim() : '',
    }),
    dir: typeof source.dir === 'string' ? source.dir.trim() : '',
  });
}

/**
 * Normalize a filesystem path for prefix comparison.
 *
 * Windows paths compare case-insensitively with forward slashes, because a
 * session's `cwd` and a hand-written policy path routinely differ in both.
 * @param value - path to normalize.
 */
export function normalizePath(value) {
  const slashed = value.replace(/\\/g, '/');
  const collapsed = slashed.replace(/\/{2,}/g, '/');
  const trimmed = collapsed.length > 1 && collapsed.endsWith('/') ? collapsed.slice(0, -1) : collapsed;
  return trimmed.toLowerCase();
}

/**
 * Whether one policy path covers a working directory.
 *
 * A trailing `/**` or `/*` is accepted as "everything below", a trailing `*`
 * as a prefix, and a bare path as either the directory itself or a prefix of it
 * — which is what a security reviewer means by "this workspace".
 * @param policyPath - configured path.
 * @param cwd - the session's working directory.
 */
export function pathCovered(policyPath, cwd) {
  const policy = normalizePath(policyPath).replace(/\/\*+$/, '');
  const target = normalizePath(cwd);
  if (policy.length === 0) return false;
  if (target === policy) return true;
  return target.startsWith(policy.endsWith('/') ? policy : `${policy}/`);
}

/**
 * Resolve the effective policy for one working directory.
 *
 * The longest matching configured path wins so a nested exception can re-enable
 * redaction inside a bypassed tree.
 * @param config - normalized config.
 * @param cwd - the session's working directory, or `undefined` when unknown.
 */
export function resolveWorkspacePolicy(config, cwd) {
  const base = {
    cwd: cwd ?? '',
    matched: '',
    policy: 'enforce',
    categories: config.categories,
    dictionary: config.dictionary,
    allowlist: config.allowlist,
    mode: config.mode,
  };
  if (typeof cwd !== 'string' || cwd.length === 0) return base;

  let best;
  let bestLength = -1;
  for (const workspace of config.workspaces) {
    if (!pathCovered(workspace.path, cwd)) continue;
    const length = normalizePath(workspace.path).replace(/\/\*+$/, '').length;
    if (length <= bestLength) continue;
    best = workspace;
    bestLength = length;
  }
  if (best === undefined) return base;

  return {
    cwd,
    matched: best.path,
    note: best.note,
    policy: best.policy,
    categories: best.categories,
    dictionary: best.dictionary,
    allowlist: best.allowlist ?? config.allowlist,
    // A bypassed workspace is bypassed whatever the global mode is; otherwise
    // an explicit `audit` on the workspace outranks `enforce`.
    mode: best.policy === 'bypass' ? 'off' : best.policy === 'audit' ? 'audit' : config.mode,
  };
}
