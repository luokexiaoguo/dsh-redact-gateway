/**
 * Model-facing tools.
 *
 * One rule governs every tool here: **nothing returned to the model may contain
 * an original value.** A tool that echoed "here is what I would redact" would be
 * a hole straight through the gateway, so previews return placeholders and
 * offsets, and the audit tools return masks and keyed fingerprints only.
 *
 * @module dsh-redact-gateway/tools
 */

import { join } from 'node:path';
import { existsSync, mkdirSync } from 'node:fs';
import { CATEGORIES, resolveWorkspacePolicy } from './config.js';
import { Vault } from './vault.js';
import { createDetector } from './rules.js';
import { createRedactor } from './redact.js';
import { maskValue } from './audit.js';

/** Render one JSON value as the tool's text content. */
function asText(_args, value) {
  return [{ type: 'text', text: JSON.stringify(value, null, 2) }];
}

/** Shared output shape for every tool that returns structured JSON. */
const JSON_OUTPUT = Object.freeze({
  schema: Object.freeze({ type: 'object', additionalProperties: true }),
  render: asText,
});

/**
 * The working directory of the calling agent, when known.
 * @param exec - tool execution context.
 */
function cwdOf(exec) {
  try {
    const cwd = exec?.agent?.session?.header?.cwd;
    return typeof cwd === 'string' ? cwd : '';
  } catch {
    return '';
  }
}

/**
 * Register the gateway's tools.
 * @param ctx - plugin context.
 * @param gateway - the gateway.
 */
export function registerTools(ctx, gateway) {
  const disposers = [];

  disposers.push(
    ctx.tools.register({
      name: 'redact_status',
      description:
        'Report the egress redaction gateway state: mode, whether protection is paused, the active workspace policy, per-category switches, and how many placeholders this session has substituted. Use it before telling the user anything about redaction behaviour.',
      parameters: {},
      output: JSON_OUTPUT,
      execute() {
        const state = gateway.state();
        return Promise.resolve({
          mode: state.mode,
          paused: state.paused,
          onError: state.onError,
          workspace: state.workspace,
          categories: state.categories,
          session: state.session,
          totals: {
            requests: state.totals.requests,
            placeholders: state.totals.placeholders,
            blocked: state.totals.blocked,
          },
          paths: { dataDir: state.paths.dataDir, auditDir: state.paths.auditDir },
        });
      },
    }),
  );

  disposers.push(
    ctx.tools.register({
      name: 'redact_preview',
      description:
        'Show which spans of a text the gateway would mask, without sending anything. Returns category, rule, placeholder and character offsets — never the matched value. Use it to explain or debug the detection rules for a specific piece of text.',
      parameters: {
        text: {
          type: 'string',
          required: true,
          description: 'Text to scan. It is not sent to any model provider.',
        },
        categories: {
          type: 'string',
          required: false,
          description: `Comma-separated subset of ${CATEGORIES.join(', ')} to scan; omit for the active workspace policy.`,
        },
      },
      output: JSON_OUTPUT,
      execute(args, exec) {
        const text = typeof args?.text === 'string' ? args.text : '';
        const policy = resolveWorkspacePolicy(gateway.config, cwdOf(exec));
        const requested = typeof args?.categories === 'string'
          ? args.categories.split(',').map((entry) => entry.trim()).filter((entry) => CATEGORIES.includes(entry))
          : [];
        const categories = { ...policy.categories };
        if (requested.length > 0) {
          for (const category of CATEGORIES) categories[category] = requested.includes(category);
        }
        // A throwaway in-memory vault: previews must never enter the session's
        // real mapping, or a previewed value would gain a live placeholder.
        const vault = Vault.open({ dir: '', sessionId: 'preview', key: Buffer.alloc(32), degraded: true });
        vault.setDelimiters(gateway.config.placeholder);
        const redactor = createRedactor({
          detector: createDetector({
            categories,
            dictionary: policy.dictionary ?? [],
            allowlist: policy.allowlist?.values ?? [],
            allowPatterns: (policy.allowlist?.patterns ?? []).map((entry) => entry.source),
            minCustomLength: gateway.config.minCustomLength,
            nameStrict: gateway.config.nameStrict,
          }),
          vault,
          policy: { ...policy, categories },
          config: gateway.config,
        });
        const masked = redactor.redactText(text);
        const spans = redactor.hits().map((hit) => ({
          category: hit.category,
          rule: hit.ruleId,
          placeholder: hit.placeholder,
          occurrences: hit.count,
          validation: hit.validation,
          mask: maskValue(hit.value, hit.category),
        }));
        return Promise.resolve({
          wouldMask: spans.length > 0,
          distinct: spans.length,
          spans,
          maskedText: masked,
        });
      },
    }),
  );

  disposers.push(
    ctx.tools.register({
      name: 'redact_audit',
      description:
        'Read recent redaction audit records. Each row carries the category, rule id, placeholder, a partial mask and a keyed fingerprint — never an original value. Use it to answer "what has this gateway masked" questions.',
      parameters: {
        limit: {
          type: 'number',
          required: false,
          description: 'How many records to return, newest last. Defaults to 50, maximum 500.',
        },
        since: {
          type: 'string',
          required: false,
          description: 'ISO timestamp or epoch milliseconds; only records at or after it are returned.',
        },
        category: {
          type: 'string',
          required: false,
          description: `Only one category: ${CATEGORIES.join(', ')}.`,
        },
      },
      output: JSON_OUTPUT,
      execute(args) {
        const limit = clamp(args?.limit, 50, 1, 500);
        const since = parseTime(args?.since);
        const category = typeof args?.category === 'string' && args.category.length > 0 ? args.category : undefined;
        const rows = gateway.audit.query({ limit, since, category });
        return Promise.resolve({
          rows: rows.map((row) => ({
            seq: row.seq,
            at: row.ts,
            session: row.sessionId,
            category: row.category,
            rule: row.ruleId,
            placeholder: row.placeholder,
            mask: row.mask,
            fingerprint: row.valueFp,
            occurrences: row.count,
            action: row.action,
            outcome: row.outcome,
          })),
        });
      },
    }),
  );

  disposers.push(
    ctx.tools.register({
      name: 'redact_export_csv',
      description:
        'Write the audit log to a CSV file for a security review and return its path. The file contains masks and keyed fingerprints, never original values. Use it when the user asks for an export or an audit trail.',
      parameters: {
        since: {
          type: 'string',
          required: false,
          description: 'ISO timestamp or epoch milliseconds; export starts here.',
        },
        until: {
          type: 'string',
          required: false,
          description: 'ISO timestamp or epoch milliseconds; export ends here.',
        },
        category: {
          type: 'string',
          required: false,
          description: 'Restrict the export to one category.',
        },
      },
      output: JSON_OUTPUT,
      execute(args) {
        const exportsDir = join(gateway.paths.root, 'exports');
        if (!existsSync(exportsDir)) mkdirSync(exportsDir, { recursive: true, mode: 0o700 });
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        const outPath = join(exportsDir, `redact-audit-${stamp}.csv`);
        const result = gateway.audit.exportCsv(
          {
            since: parseTime(args?.since),
            until: parseTime(args?.until),
            category: typeof args?.category === 'string' && args.category.length > 0 ? args.category : undefined,
          },
          outPath,
        );
        return Promise.resolve({
          ok: result.path.length > 0,
          path: result.path,
          rows: result.rows,
          columns: [
            'seq',
            'timestamp_utc',
            'session_id',
            'workspace_fp',
            'provider',
            'model',
            'direction',
            'action',
            'category',
            'rule_id',
            'placeholder',
            'mask',
            'value_fp',
            'validation',
            'occurrences',
            'outcome',
            'prev_hash',
            'record_hash',
          ],
        });
      },
    }),
  );

  disposers.push(
    ctx.tools.register({
      name: 'redact_dictionary',
      description:
        'List, add or remove sensitive terms (customer names, project codenames, internal product names) in the redaction dictionary. Added terms become a placeholder like any detected value. Requires user intent: only add terms the user named.',
      parameters: {
        action: {
          type: 'string',
          required: true,
          enum: ['list', 'add', 'remove'],
          description: 'Which operation to perform.',
        },
        value: {
          type: 'string',
          required: false,
          description: 'The term to add or remove; required for add and remove.',
        },
      },
      output: JSON_OUTPUT,
      execute(args) {
        const action = typeof args?.action === 'string' ? args.action : 'list';
        const value = typeof args?.value === 'string' ? args.value.trim() : '';
        if (action === 'list') return Promise.resolve({ terms: [...gateway.config.dictionary] });
        if (value.length === 0) {
          return Promise.resolve({ ok: false, error: 'value is required for add and remove' });
        }
        const current = new Set(gateway.config.dictionary);
        if (action === 'add') current.add(value);
        else if (action === 'remove') current.delete(value);
        else return Promise.resolve({ ok: false, error: `unknown action "${action}"` });
        const result = gateway.applyConfig({ dictionary: [...current] });
        return Promise.resolve({
          ok: true,
          applied: result.applied,
          persisted: result.persisted,
          terms: [...gateway.config.dictionary],
        });
      },
    }),
  );

  return () => {
    for (const dispose of disposers) {
      try {
        dispose();
      } catch {
        /* the registry is already gone */
      }
    }
  };
}

/** Clamp a numeric argument. */
function clamp(value, fallback, min, max) {
  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(numeric)));
}

/** Parse an ISO timestamp or epoch milliseconds. */
function parseTime(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.length > 0) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}
