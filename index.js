/**
 * 出网脱敏网关 / Egress redaction gateway.
 *
 * DSH sends prompts, tool results and attachments to a model provider verbatim.
 * This plugin intercepts every streaming model call, replaces detectable
 * personal data and secrets with numbered placeholders, sends the masked copy,
 * restores the response, and keeps a tamper-evident audit trail — so an
 * organization can hand its internal documents to a cloud model without the
 * model ever seeing an identity number, a phone number, a customer name or a key.
 *
 * The interception point is `llm/stream`; see `lib/gateway.js` for why the
 * request has to be re-dispatched rather than rewritten.
 *
 * @module dsh-redact-gateway
 */

import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { normalizeConfig, CATEGORIES } from './lib/config.js';
import { Gateway } from './lib/gateway.js';
import { registerTools } from './lib/tools.js';
import { registerRoutes } from './lib/http.js';

export const name = 'redact-gateway';

/**
 * The gateway cannot work without the LLM seam or the tool registry. Declaring
 * them keeps the plugin inactive in a composition that has neither instead of
 * throwing during activation.
 *
 * This must stay a *named* export: the Loader resolves a module's `default`
 * export first and discards its siblings, so a `export default apply` here would
 * drop both `inject` and this name.
 */
export const inject = ['llm', 'tools'];

/** Prompt text explaining the placeholder contract to the model. */
const PROMPT_HINT = [
  '【出网脱敏网关】本对话中的部分内容已被本地网关替换为编号占位符，例如 `[EMAIL_1]`、`[IDCARD_2]`、`[CUSTOMER_1]`。',
  '规则：',
  '1. 这些占位符是**不透明标识**，代表一个真实值。原样复制它们，不要翻译、改写、加空格、换括号或试图推测其内容。',
  '2. 需要引用同一实体时，重复使用同一个占位符，不要新建占位符。',
  '3. 回复会由网关自动回填为真实值，用户看不到占位符；因此不要在回答里解释占位符机制，除非用户主动问。',
  '4. 如果某处显然需要真实值才能继续（例如必须读取一个文件路径），说明缺少的信息，不要猜测。',
  '',
  '[Egress redaction gateway] Parts of this conversation were replaced by a local gateway with numbered placeholders such as `[EMAIL_1]` or `[IDCARD_2]`. Treat each placeholder as an opaque identifier for a real value: reproduce it verbatim (same brackets, same spelling, same number), reuse the same placeholder for the same entity, never invent placeholders, and never try to guess or explain the underlying value. The gateway restores real values before the user reads your reply.',
].join('\n');

/**
 * Resolve the directories this plugin owns.
 * @param config - normalized config.
 * @returns absolute paths with the vault time-to-live attached.
 */
function resolvePaths(config) {
  const home = process.env.DSH_HOME && process.env.DSH_HOME.length > 0
    ? process.env.DSH_HOME
    : join(homedir(), '.dsh');
  const root = resolve(config.dir.length > 0 ? config.dir : join(home, 'redact-gateway'));
  const audit = config.audit.dir.length > 0 ? resolve(config.audit.dir) : join(root, 'audit');
  return {
    root,
    sessions: join(root, 'sessions'),
    audit,
    vaultTtlHours: config.vaultTtlHours,
  };
}

/**
 * Mount the gateway.
 * @param ctx - plugin context.
 * @param rawConfig - the Loader row's config, of unknown shape.
 */
export function apply(ctx, rawConfig = {}) {
  const warn = (message) => ctx.logger?.warn?.(`redact-gateway: ${message}`);
  const config = normalizeConfig(rawConfig, warn);
  const paths = resolvePaths(config);

  ctx.logger?.info?.(
    `redact-gateway: mode=${config.mode} onError=${config.onError} data=${paths.root} categories=${CATEGORIES.filter(
      (category) => config.categories[category],
    ).join(',')}`,
  );

  const gateway = new Gateway({
    ctx,
    config,
    paths,
    warn,
    log: ctx.logger,
  });

  // `prepend` puts the gate in front of every other llm/stream listener, so the
  // request that reaches them — and the provider — is already masked.
  const disposeStream = ctx.on(
    'llm/stream',
    (options, next) => gateway.handleStream(options, next),
    { prepend: true, global: true },
  );

  const disposeTools = registerTools(ctx, gateway);

  // Optional seams are acquired through `ctx.inject` rather than read once at
  // activation: a service that is still initializing (the web server and the
  // settings store are both async) would otherwise be silently missed for the
  // life of the process. Each call starts a child fiber, which owns whatever the
  // callback registers and removes it on dispose.
  const optionalFibers = [
    ctx.inject(['webServer'], (sub) => {
      registerRoutes(sub, gateway, { warn });
    }),
    ctx.inject(['systemPrompt'], (sub) => {
      if (!config.promptHint) return;
      sub.systemPrompt.section({
        name: 'redact-gateway',
        order: 50,
        text: PROMPT_HINT,
      });
    }),
    ctx.inject(['commands'], (sub) => {
      sub.commands.register({
        name: 'redact',
        description:
          '出网脱敏网关：status 查看状态，pause [分钟] 临时暂停，resume 恢复，export [天数] 导出审计 CSV，verify 校验审计链。',
        recordInput: false,
        handler: (invocation) => runCommand(gateway, invocation, warn),
      });
    }),
  ];

  ctx.effect(
    () => () => {
      for (const fiber of optionalFibers.splice(0)) {
        try {
          fiber?.dispose?.();
        } catch {
          /* the owning service is already gone */
        }
      }
      disposeTools?.();
      disposeStream?.();
      gateway.dispose();
    },
    'redact-gateway: release the gateway',
  );

  ctx.logger?.info?.('redact-gateway: egress interception active');
}

/**
 * Handle one `/redact` invocation.
 * @param gateway - the gateway.
 * @param invocation - the command invocation.
 * @param warn - diagnostic sink.
 * @returns the command result.
 */
function runCommand(gateway, invocation, warn) {
  const raw = typeof invocation?.rawInput === 'string' ? invocation.rawInput.trim() : '';
  const [verb = 'status', argument] = raw.split(/\s+/);
  switch (verb.toLowerCase()) {
    case 'status': {
      const state = gateway.state();
      return {
        kind: 'success',
        text: [
          `出网脱敏网关 v${state.version}`,
          `模式：${state.mode}${state.paused ? `（已暂停至 ${new Date(state.pausedUntil).toLocaleString()}）` : ''}，失败策略：${state.onError}`,
          `工作区：${state.workspace.path || '(未知)'} → ${state.workspace.policy}${
            state.workspace.matched ? `（匹配 ${state.workspace.matched}）` : ''
          }`,
          `本会话：${state.session.placeholders} 个占位符 / ${state.session.requests} 次请求`,
          `累计：${state.totals.placeholders} 个占位符 / ${state.totals.requests} 次请求，拦截 ${state.totals.blocked} 次`,
          `审计目录：${state.paths.auditDir}`,
        ].join('\n'),
      };
    }
    case 'pause': {
      const minutes = Number.parseInt(argument ?? '30', 10);
      const horizon = gateway.pause((Number.isFinite(minutes) ? Math.max(1, minutes) : 30) * 60_000);
      return {
        kind: 'success',
        text: `已临时暂停出网脱敏，至 ${new Date(horizon).toLocaleString()}。期间请求将按原文发送，并记录 pause-skip 审计。`,
      };
    }
    case 'resume':
      gateway.resume();
      return { kind: 'success', text: '已恢复出网脱敏。' };
    case 'export': {
      const exportsDir = join(gateway.paths.root, 'exports');
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      const since = argument === undefined ? undefined : Number.parseInt(argument, 10) * 86_400_000;
      const result = gateway.audit.exportCsv(
        { since: since === undefined ? undefined : Date.now() - since },
        join(exportsDir, `redact-audit-${stamp}.csv`),
      );
      if (result.path.length === 0) return { kind: 'error', text: '导出失败：审计文件无法写入，请查看 DSH 日志。' };
      return { kind: 'success', text: `已导出 ${result.rows} 行审计记录到 ${result.path}` };
    }
    case 'verify': {
      const verification = gateway.audit.verifyChain();
      return verification.ok
        ? { kind: 'success', text: `审计链完整：${verification.records} 条记录，链头 ${verification.head.slice(0, 16)}…` }
        : { kind: 'error', text: `审计链在序号 ${verification.brokenAt} 处断裂（${verification.reason}）。` };
    }
    default: {
      warn(`unknown /redact subcommand "${verb}"`);
      return {
        kind: 'error',
        text: `未知子命令 "${verb}"。可用：status | pause [分钟] | resume | export [天数] | verify`,
      };
    }
  }
}
