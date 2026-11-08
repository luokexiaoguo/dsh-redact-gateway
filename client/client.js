/**
 * 出网脱敏网关 — 设置页 Web UI。
 *
 * 以 `settings.section` 的列表条目注册一页设置界面，数据全部来自
 * `GET /dsh-redact-gateway/state`，写操作走 `POST /dsh-redact-gateway/config`
 * 与 `POST /dsh-redact-gateway/export`。
 *
 * 约束（DSH 浏览器插件装载协议）：
 * - 工厂函数无副作用，注册只发生在 `apply(ctx)` 里，并全部用 `ctx.effect` 拥有；
 * - 运行时只 require `react`，样式是组件内联的 `<style>` 元素；
 * - 不改写页面其它 DOM，不写全局 CSS，不做硬跳转；
 * - 颜色只使用宿主 `--dsw-alias-*` 主题 token。
 */

window.__ModuleLoader__.load({
  id: 'dsh-redact-gateway',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useState, useEffect, useRef, useCallback } = React;

    const NS = 'redact-gateway';
    const SECTION_ID = 'dsh-redact-gateway';
    const API = '/dsh-redact-gateway';
    const POLL_MS = 15000;
    const MAX_RECENT = 20;
    const CATEGORIES = [
      'secret',
      'idcard',
      'bankcard',
      'phone',
      'email',
      'address',
      'name',
      'org',
      'custom',
    ];
    const MODES = ['enforce', 'audit', 'off'];

    /* ------------------------------------------------------------------ *
     * 文案字典（与 locale/*.json 的 meta 对应；这里供 ctx.locale 使用）
     * ------------------------------------------------------------------ */

    const EN = {
      nav: 'Outbound redaction gateway',
      intro:
        'Detects and replaces ID numbers, phone numbers, bank cards, email addresses, addresses, customer names and secrets before a request leaves this machine; the model only sees placeholders.',

      'mode.title': 'Protection mode',
      'mode.hint': 'Applies to this session right away and is saved by the Host.',
      'mode.segLabel': 'Mode',
      'mode.enforce': 'Enforce',
      'mode.audit': 'Audit only',
      'mode.off': 'Off',
      'mode.enforce.hint':
        'Replaces sensitive values before every outbound request and blocks the request when redaction fails.',
      'mode.audit.hint':
        'Records what would be replaced without changing the request; the model still receives the original text.',
      'mode.off.hint': 'Passes requests through unchanged and writes no audit records.',
      'mode.pauseTitle': 'Pause protection',
      'mode.pauseHint': 'Temporarily pauses redaction for every workspace; the audit log records the skip.',
      'mode.pause': 'Pause protection',
      'mode.resume': 'Resume protection',
      'mode.working': 'Working…',
      'mode.pausedBadge': 'Paused',
      'mode.pausedHint': 'Protection is paused, so requests leave unredacted until you resume.',
      'mode.pausedUntil': 'Protection is paused until {time}.',

      'status.title': 'This session',
      'status.hint': 'Session counts restart when this page reloads; totals accumulate across sessions.',
      'stat.sessionPlaceholders': 'Session placeholders',
      'stat.sessionRequests': 'Session requests',
      'stat.totalPlaceholders': 'Total placeholders',
      'stat.totalRequests': 'Total requests',
      'stat.blocked': 'Blocked requests',
      'stat.lastAt': 'Last replacement',
      'status.never': 'Not yet',
      'stat.none': 'No replacements recorded yet.',

      'cat.title': 'Categories',
      'cat.hint': 'Turn a category off to leave that kind of value untouched.',
      'cat.secret': 'Secrets and keys',
      'cat.secret.hint': 'API keys, access tokens, private key blocks and connection strings.',
      'cat.idcard': 'ID numbers',
      'cat.idcard.hint': 'Resident ID numbers that pass the checksum.',
      'cat.bankcard': 'Bank cards',
      'cat.bankcard.hint': 'Card numbers that pass the Luhn check.',
      'cat.phone': 'Phone numbers',
      'cat.phone.hint': 'Mainland mobile numbers detected by number segment.',
      'cat.email': 'Email addresses',
      'cat.email.hint': 'Mailbox addresses found in text.',
      'cat.address': 'Addresses',
      'cat.address.hint': 'Street addresses and administrative divisions.',
      'cat.name': 'Person names',
      'cat.name.hint': 'Heuristic detection from a surname list.',
      'cat.org': 'Organizations',
      'cat.org.hint': 'Company and customer names.',
      'cat.custom': 'Custom dictionary',
      'cat.custom.hint': 'Entries added to the dictionary.',

      'workspace.title': 'Workspace policy',
      'workspace.hint':
        'The longest matching path prefix decides whether this workspace is enforced, audited or bypassed.',
      'workspace.current': 'Current workspace',
      'workspace.policy': 'Policy',
      'workspace.matched': 'Matched prefix',
      'workspace.col.path': 'Path',
      'workspace.col.policy': 'Policy',
      'workspace.col.matched': 'Matched',
      'workspace.active': 'Current',
      'workspace.empty': 'No workspace override is configured, so the global mode applies.',
      'policy.enforce': 'Enforce',
      'policy.audit': 'Audit',
      'policy.bypass': 'Bypass',

      'recent.title': 'Recent replacements',
      'recent.hint':
        'The latest 20 records. Only masked values are stored and shown; the original text never reaches this page.',
      'recent.time': 'Time',
      'recent.category': 'Category',
      'recent.mask': 'Masked value',
      'recent.placeholder': 'Placeholder',
      'recent.session': 'Session',
      'recent.empty': 'No replacements recorded yet.',
      'recent.direction.out': 'Out',
      'recent.direction.in': 'In',

      'export.title': 'Export audit log',
      'export.hint': 'Writes the masked audit records on the Host and downloads the CSV in this browser.',
      'export.button': 'Export CSV',
      'export.busy': 'Exporting…',
      'export.done': 'Exported {rows} rows.',
      'export.path': 'Saved to',
      'export.tooLarge': 'The file is too large to download here; it was written on the Host instead.',

      'footer.dataDir': 'Data directory',
      'footer.auditDir': 'Audit directory',
      'footer.vaultDir': 'Mapping directory',
      'footer.key': 'Key source',
      'footer.keyValue':
        'AES-256-GCM master key from {file} (mode 0600) or the DSH_REDACT_KEY environment variable.',
      'footer.onError': 'On failure',
      'errorPolicy.block': 'Block the request',
      'errorPolicy.pass': 'Pass the request through',
      'footer.how': 'How this works',
      'footer.how1':
        'Local rules and dictionaries detect sensitive values before a request leaves this machine and replace them with placeholders such as a@b.com.',
      'footer.how2':
        'The mapping table is encrypted with AES-256-GCM and stored in the local data directory; the provider only ever sees placeholders.',
      'footer.how3':
        'Placeholders are filled back into the response, and every replacement writes an audit record that contains only a mask and a salted hash.',

      'error.auth': 'Sign in to DSH Web or refresh this page, then try again.',
      'error.network': 'Cannot reach the gateway. Check that the Host is still running.',
      'error.http': 'The gateway answered HTTP {status}.',
      'error.unknown': 'The request failed for an unknown reason.',
      'error.retry': 'Retry',
      'error.title': 'The gateway settings page failed to render',
      'common.dismiss': 'Dismiss',
    };

    const ZH = {
      nav: '出网脱敏网关',
      intro:
        '在请求出网前识别并替换身份证、手机号、银行卡、邮箱、地址、客户名与密钥，模型全程看不到原文。',

      'mode.title': '防护模式',
      'mode.hint': '立即对本会话生效，宿主会保存该设置。',
      'mode.segLabel': '模式',
      'mode.enforce': '强制',
      'mode.audit': '仅审计',
      'mode.off': '关闭',
      'mode.enforce.hint': '每次出网前替换敏感值；脱敏流程失败时阻断该请求。',
      'mode.audit.hint': '只记录将要替换的内容、不改写请求；模型仍会收到原文。',
      'mode.off.hint': '请求原样放行，不写审计记录。',
      'mode.pauseTitle': '暂停保护',
      'mode.pauseHint': '临时暂停所有工作区的脱敏，审计日志会记录这次跳过。',
      'mode.pause': '暂停保护',
      'mode.resume': '恢复保护',
      'mode.working': '处理中…',
      'mode.pausedBadge': '已暂停',
      'mode.pausedHint': '保护已暂停，恢复前请求会以原文出网。',
      'mode.pausedUntil': '保护已暂停至 {time}。',

      'status.title': '本会话',
      'status.hint': '会话计数在页面刷新后重新统计，累计值跨会话累加。',
      'stat.sessionPlaceholders': '本会话占位符',
      'stat.sessionRequests': '本会话请求',
      'stat.totalPlaceholders': '累计占位符',
      'stat.totalRequests': '累计请求',
      'stat.blocked': '已阻断请求',
      'stat.lastAt': '最近替换时间',
      'status.never': '暂无',
      'stat.none': '暂无替换记录。',

      'cat.title': '识别类别',
      'cat.hint': '关闭某个类别后，该类数值将不再被替换。',
      'cat.secret': '密钥与凭据',
      'cat.secret.hint': 'API Key、访问令牌、私钥块与连接串。',
      'cat.idcard': '身份证号',
      'cat.idcard.hint': '通过校验位验证的居民身份证号。',
      'cat.bankcard': '银行卡号',
      'cat.bankcard.hint': '通过 Luhn 校验的银行卡号。',
      'cat.phone': '手机号',
      'cat.phone.hint': '按号段识别的大陆手机号。',
      'cat.email': '邮箱',
      'cat.email.hint': '文本中的邮箱地址。',
      'cat.address': '地址',
      'cat.address.hint': '街道地址与行政区划描述。',
      'cat.name': '人名',
      'cat.name.hint': '基于姓氏表的启发式识别。',
      'cat.org': '机构与客户名',
      'cat.org.hint': '公司名与客户名。',
      'cat.custom': '自定义词典',
      'cat.custom.hint': '添加到词典中的条目。',

      'workspace.title': '工作区策略',
      'workspace.hint': '最长匹配的路径前缀决定该工作区是强制、审计还是放行。',
      'workspace.current': '当前工作区',
      'workspace.policy': '策略',
      'workspace.matched': '命中的前缀',
      'workspace.col.path': '路径',
      'workspace.col.policy': '策略',
      'workspace.col.matched': '命中',
      'workspace.active': '当前',
      'workspace.empty': '未配置工作区覆盖，使用全局模式。',
      'policy.enforce': '强制',
      'policy.audit': '审计',
      'policy.bypass': '放行',

      'recent.title': '最近替换',
      'recent.hint': '最近 20 条记录。仅保存并展示掩码值，原文不会出现在此页面。',
      'recent.time': '时间',
      'recent.category': '类别',
      'recent.mask': '掩码值',
      'recent.placeholder': '占位符',
      'recent.session': '会话',
      'recent.empty': '暂无替换记录。',
      'recent.direction.out': '出网',
      'recent.direction.in': '回填',

      'export.title': '导出审计日志',
      'export.hint': '把掩码后的审计记录写入宿主文件，并在浏览器中下载 CSV。',
      'export.button': '导出 CSV',
      'export.busy': '正在导出…',
      'export.done': '已导出 {rows} 行。',
      'export.path': '落盘路径',
      'export.tooLarge': '文件过大，无法在此下载，已改为写入宿主文件。',

      'footer.dataDir': '数据目录',
      'footer.auditDir': '审计目录',
      'footer.vaultDir': '映射表目录',
      'footer.key': '密钥来源',
      'footer.keyValue': 'AES-256-GCM 主密钥来自 {file}（权限 0600），或环境变量 DSH_REDACT_KEY。',
      'footer.onError': '失败策略',
      'errorPolicy.block': '阻断请求',
      'errorPolicy.pass': '放行原文',
      'footer.how': '这是怎么工作的',
      'footer.how1': '请求出网前，本地规则与词典识别敏感值，替换成 a@b.com 这类占位符。',
      'footer.how2': '映射表用 AES-256-GCM 加密保存在本机数据目录，服务商只能看到占位符。',
      'footer.how3': '响应返回后自动回填占位符；每次替换写一条只含掩码与加盐哈希的审计记录。',

      'error.auth': '请先登录 DSH Web 或刷新页面，然后重试。',
      'error.network': '无法连接到网关，请确认宿主仍在运行。',
      'error.http': '网关返回 HTTP {status}。',
      'error.unknown': '请求失败，原因未知。',
      'error.retry': '重试',
      'error.title': '网关设置页渲染失败',
      'common.dismiss': '关闭',
    };

    /* ------------------------------------------------------------------ *
     * 样式：只引用宿主主题 token，颜色不写死；卸载时随组件一起消失。
     * ------------------------------------------------------------------ */

    const CSS = `
.rgw-root{box-sizing:border-box;display:flex;flex-direction:column;gap:20px;max-width:720px;padding-bottom:24px;color:var(--dsw-alias-label-primary);font-family:inherit;font-size:14px;line-height:22px}
.rgw-head{display:flex;flex-direction:column;gap:6px}
.rgw-headrow{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.rgw-title{margin:0;font-size:16px;font-weight:500;line-height:24px;color:var(--dsw-alias-label-primary)}
.rgw-intro{margin:0;font-size:14px;line-height:22px;color:var(--dsw-alias-label-tertiary)}
.rgw-badge{display:inline-flex;align-items:center;padding:1px 8px;border-radius:999px;font-size:12px;line-height:18px;white-space:nowrap;border:.5px solid transparent}
.rgw-badge-success{color:var(--dsw-alias-state-success-primary);background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 12%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-success-primary) 30%,transparent)}
.rgw-badge-business{color:var(--dsw-alias-state-business-primary);background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 12%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 30%,transparent)}
.rgw-badge-warn{color:var(--dsw-alias-state-warn-label);background:color-mix(in srgb,var(--dsw-alias-state-warn-primary) 14%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-warn-primary) 32%,transparent)}
.rgw-badge-idle{color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-multi-select);border-color:var(--dsw-alias-border-l2)}
.rgw-error{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border-radius:8px;font-size:13px;line-height:20px;color:var(--dsw-alias-state-error-primary);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 10%,transparent);border:.5px solid color-mix(in srgb,var(--dsw-alias-state-error-primary) 32%,transparent)}
.rgw-error-body{flex:1;min-width:0;overflow-wrap:anywhere}
.rgw-error-detail{margin-top:2px;color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
.rgw-section{display:flex;flex-direction:column;gap:10px;min-width:0}
.rgw-section-head{display:flex;flex-direction:column;gap:2px}
.rgw-section-title{margin:0;font-size:14px;font-weight:500;line-height:22px;color:var(--dsw-alias-label-primary)}
.rgw-section-hint{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}
.rgw-card{border:.5px solid var(--dsw-alias-settings-card-stroke);background:var(--dsw-alias-settings-card-fill);border-radius:8px;overflow:hidden}
.rgw-row{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:12px 14px;border-bottom:.5px solid var(--dsw-alias-border-l2)}
.rgw-row:last-child{border-bottom:none}
.rgw-row-text{display:flex;flex-direction:column;gap:2px;min-width:0}
.rgw-row-label{font-size:14px;line-height:20px;color:var(--dsw-alias-label-primary)}
.rgw-row-desc{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}
.rgw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.rgw-stat{display:flex;flex-direction:column;gap:2px;min-width:0;padding:10px 12px;border:.5px solid var(--dsw-alias-settings-card-stroke);background:var(--dsw-alias-settings-card-fill);border-radius:8px}
.rgw-stat-label{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}
.rgw-stat-value{font-size:20px;line-height:28px;font-weight:600;color:var(--dsw-alias-label-primary);font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.rgw-stat-value-sm{font-size:13px;line-height:20px;font-weight:500;font-variant-numeric:tabular-nums}
.rgw-chips{display:flex;flex-wrap:wrap;gap:6px;padding:12px 14px}
.rgw-chip{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:999px;background:var(--dsw-alias-bg-multi-select);font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);white-space:nowrap}
.rgw-chip strong{font-weight:600;color:var(--dsw-alias-label-primary);font-variant-numeric:tabular-nums}
.rgw-empty{padding:14px;font-size:13px;line-height:20px;color:var(--dsw-alias-label-tertiary)}
.rgw-table-wrap{overflow-x:auto}
.rgw-table{width:100%;border-collapse:collapse;font-size:13px;line-height:20px}
.rgw-table th{text-align:left;padding:8px 14px;border-bottom:.5px solid var(--dsw-alias-border-l2);color:var(--dsw-alias-label-secondary);font-size:12px;font-weight:400;line-height:18px;white-space:nowrap}
.rgw-table td{padding:8px 14px;border-bottom:.5px solid var(--dsw-alias-border-l2);color:var(--dsw-alias-label-primary);vertical-align:top}
.rgw-table tr:last-child td{border-bottom:none}
.rgw-mono{font-family:var(--dsh-font-family-code-default,ui-monospace,SFMono-Regular,Menlo,Consolas,monospace);font-size:12px;line-height:18px}
.rgw-dim{color:var(--dsw-alias-label-tertiary)}
.rgw-accent{color:var(--dsw-alias-state-business-primary)}
.rgw-nowrap{white-space:nowrap}
.rgw-clip{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rgw-path{overflow-wrap:anywhere;word-break:break-all}
.rgw-tag{display:inline-flex;padding:0 6px;margin-right:4px;border:.5px solid var(--dsw-alias-border-l3);border-radius:4px;font-size:11px;line-height:16px;color:var(--dsw-alias-label-secondary);white-space:nowrap}
.rgw-tag-active{color:var(--dsw-alias-state-business-primary);border-color:color-mix(in srgb,var(--dsw-alias-state-business-primary) 40%,transparent)}
.rgw-btn{font-family:inherit;font-size:13px;line-height:20px;padding:4px 12px;border:.5px solid var(--dsw-alias-border-l4);border-radius:8px;background:transparent;color:var(--dsw-alias-label-primary);cursor:pointer;white-space:nowrap;transition:background-color .12s ease,border-color .12s ease}
.rgw-btn:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}
.rgw-btn:disabled{opacity:.45;cursor:default}
.rgw-btn-primary{background:var(--dsw-alias-button-primary-fill);border-color:transparent;color:var(--dsw-alias-label-primary-inverted)}
.rgw-btn-primary:hover:not(:disabled){background:var(--dsw-alias-button-primary-hover)}
.rgw-btn-warn{background:color-mix(in srgb,var(--dsw-alias-state-warn-primary) 12%,transparent);border-color:color-mix(in srgb,var(--dsw-alias-state-warn-primary) 36%,transparent);color:var(--dsw-alias-state-warn-label)}
.rgw-btn:focus-visible,.rgw-switch:focus-visible,.rgw-seg-btn:focus-visible,.rgw-summary:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:2px}
.rgw-seg{display:inline-flex;gap:2px;padding:2px;border-radius:8px;background:var(--dsw-alias-bg-multi-select);flex:none}
.rgw-seg-btn{font-family:inherit;font-size:13px;line-height:20px;padding:4px 14px;border:none;border-radius:6px;background:transparent;color:var(--dsw-alias-label-secondary);cursor:pointer;white-space:nowrap}
.rgw-seg-btn[aria-pressed=true]{background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-inverted);font-weight:500}
.rgw-seg-btn:disabled{opacity:.5;cursor:default}
.rgw-switch{position:relative;flex:none;width:36px;height:20px;padding:0;border:none;border-radius:10px;background:var(--dsw-alias-bg-multi-select);cursor:pointer;transition:background-color .12s ease}
.rgw-switch[aria-checked=true]{background:var(--dsw-alias-state-business-primary)}
.rgw-switch::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--dsw-alias-switch-thumb);transition:transform .12s ease}
.rgw-switch[aria-checked=true]::after{transform:translateX(16px)}
.rgw-switch:disabled{opacity:.45;cursor:default}
.rgw-footer{display:flex;flex-direction:column;gap:8px;padding-top:14px;border-top:.5px solid var(--dsw-alias-border-l2);font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}
.rgw-footer-row{display:flex;gap:8px;flex-wrap:wrap;min-width:0}
.rgw-footer-key{flex:none;color:var(--dsw-alias-label-secondary)}
.rgw-footer-val{min-width:0;color:var(--dsw-alias-label-tertiary);overflow-wrap:anywhere}
.rgw-details{margin-top:2px}
.rgw-summary{cursor:pointer;color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
.rgw-how{display:flex;flex-direction:column;gap:4px;margin:6px 0 0;padding-left:18px;color:var(--dsw-alias-label-tertiary)}
.rgw-skel{background:var(--dsw-alias-bg-skeleton);border-radius:8px;animation:rgw-pulse 1.4s ease-in-out infinite}
@keyframes rgw-pulse{0%,100%{opacity:1}50%{opacity:.55}}
@media (prefers-reduced-motion:reduce){.rgw-skel{animation:none}.rgw-switch,.rgw-switch::after{transition:none}}
@media (max-width:560px){.rgw-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.rgw-row{flex-wrap:wrap}.rgw-row>.rgw-seg{width:100%;justify-content:space-between}.rgw-clip{max-width:120px}}
`;

    /* ------------------------------------------------------------------ *
     * 纯工具函数（无副作用）
     * ------------------------------------------------------------------ */

    /** 数字 → 本地化字符串；非数字按 0 显示。 */
    function formatCount(value) {
      const numeric = typeof value === 'number' ? value : Number(value);
      return Number.isFinite(numeric) ? numeric.toLocaleString() : '0';
    }

    /** 毫秒或秒级时间戳 → Date；无效返回 null。 */
    function toDate(value) {
      const numeric = typeof value === 'number' ? value : Number(value);
      if (!Number.isFinite(numeric) || numeric <= 0) return null;
      const date = new Date(numeric < 1000000000000 ? numeric * 1000 : numeric);
      return Number.isNaN(date.getTime()) ? null : date;
    }

    /** 时间戳 → 本地化时间文案。 */
    function formatTime(value, t) {
      const date = toDate(value);
      return date === null ? t('status.never') : date.toLocaleString();
    }

    /** 把 fetch/解析错误收敛成渲染用的结构。 */
    function normalizeError(error) {
      if (!error || typeof error !== 'object') return { code: 'unknown' };
      if (error.name === 'AbortError') return { code: 'aborted' };
      const code = error.code;
      if (code === 'auth' || code === 'network' || code === 'http' || code === 'server') {
        return error;
      }
      return { code: 'network', detail: error.message ? String(error.message) : String(error) };
    }

    /**
     * 同源 JSON 请求。
     * @param {string} url - 同源相对地址。
     * @param {object} [init] - fetch 选项。
     * @returns {Promise<object>} 解析后的 JSON。
     */
    async function readJson(url, init) {
      const options = Object.assign(
        { credentials: 'same-origin', cache: 'no-store' },
        init || {},
      );
      let response;
      try {
        response = await fetch(url, options);
      } catch (error) {
        if (error && error.name === 'AbortError') throw { code: 'aborted' };
        throw {
          code: 'network',
          detail: error && error.message ? String(error.message) : String(error),
        };
      }

      let text = '';
      try {
        text = await response.text();
      } catch (error) {
        text = '';
      }
      let data = null;
      if (text) {
        try {
          data = JSON.parse(text);
        } catch (error) {
          data = null;
        }
      }

      if (!response.ok) {
        const detail =
          data && (data.error || data.message)
            ? String(data.error || data.message)
            : String(text || '').slice(0, 240);
        if (response.status === 401 || response.status === 403) {
          throw { code: 'auth', status: response.status, detail };
        }
        throw { code: 'http', status: response.status, detail };
      }
      if (data && data.ok === false) {
        throw {
          code: 'server',
          status: response.status,
          detail: data.error ? String(data.error) : '',
        };
      }
      return data && typeof data === 'object' ? data : {};
    }

    /**
     * 触发浏览器下载（CSV 文本；缺 BOM 时补上）。
     * @returns {boolean} 是否成功发起下载。
     */
    function downloadCsv(root, filename, csvText) {
      if (typeof document === 'undefined' || typeof Blob === 'undefined') return false;
      if (typeof csvText !== 'string' || csvText.length === 0) return false;
      const body = csvText.charCodeAt(0) === 0xfeff ? csvText : '\ufeff' + csvText;
      const blob = new Blob([body], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename || 'redact-audit.csv';
      anchor.rel = 'noopener';
      anchor.style.display = 'none';
      if (root && root.appendChild) root.appendChild(anchor);
      anchor.click();
      if (anchor.parentNode) anchor.parentNode.removeChild(anchor);
      setTimeout(() => {
        try {
          URL.revokeObjectURL(url);
        } catch (error) {
          /* 已被回收 */
        }
      }, 4000);
      return true;
    }

    /* ------------------------------------------------------------------ *
     * 展示组件
     * ------------------------------------------------------------------ */

    function Badge({ tone, children }) {
      return h(
        'span',
        { className: 'rgw-badge rgw-badge-' + (tone || 'idle') },
        children,
      );
    }

    function Section({ title, hint, children }) {
      return h(
        'section',
        { className: 'rgw-section' },
        h(
          'div',
          { className: 'rgw-section-head' },
          h('h3', { className: 'rgw-section-title' }, title),
          hint ? h('p', { className: 'rgw-section-hint' }, hint) : null,
        ),
        children,
      );
    }

    function Row({ label, desc, children }) {
      return h(
        'div',
        { className: 'rgw-row' },
        h(
          'div',
          { className: 'rgw-row-text' },
          h('span', { className: 'rgw-row-label' }, label),
          desc ? h('span', { className: 'rgw-row-desc' }, desc) : null,
        ),
        children,
      );
    }

    function Stat({ label, value, small }) {
      return h(
        'div',
        { className: 'rgw-stat' },
        h('span', { className: 'rgw-stat-label' }, label),
        h(
          'span',
          { className: 'rgw-stat-value' + (small ? ' rgw-stat-value-sm' : '') },
          value,
        ),
      );
    }

    function Switch({ checked, disabled, label, onChange }) {
      return h('button', {
        type: 'button',
        role: 'switch',
        className: 'rgw-switch',
        'aria-checked': checked ? 'true' : 'false',
        'aria-label': label,
        disabled: Boolean(disabled),
        onClick: onChange,
      });
    }

    function SectionIcon(ownerProps) {
      const props = ownerProps || {};
      const size = typeof props.size === 'number' && props.size > 0 ? props.size : 16;
      return h(
        'svg',
        {
          width: size,
          height: size,
          viewBox: '0 0 24 24',
          fill: 'none',
          'aria-hidden': 'true',
          focusable: 'false',
          style: { display: 'block', pointerEvents: 'none', opacity: props.active ? 1 : 0.85 },
        },
        h('path', {
          d: 'M12 3 L19.4 5.7 V11.5 C19.4 15.9 16.4 19.2 12 20.7 C7.6 19.2 4.6 15.9 4.6 11.5 V5.7 Z',
          stroke: 'currentColor',
          strokeWidth: 1.5,
          strokeLinejoin: 'round',
        }),
        h('rect', { x: 8.3, y: 8.4, width: 7.4, height: 1.6, rx: 0.8, fill: 'currentColor' }),
        h('rect', { x: 8.3, y: 11.2, width: 2.5, height: 1.6, rx: 0.8, fill: 'currentColor' }),
        h('rect', { x: 13.2, y: 11.2, width: 2.5, height: 1.6, rx: 0.8, fill: 'currentColor' }),
        h('rect', { x: 8.3, y: 13.9, width: 7.4, height: 1.6, rx: 0.8, fill: 'currentColor' }),
      );
    }

    /* ------------------------------------------------------------------ *
     * 设置页
     * ------------------------------------------------------------------ */

    function Page(ownerProps) {
      const props = ownerProps || {};
      const t = typeof props.t === 'function' ? props.t : (key) => key;

      const rootRef = useRef(null);
      const mountedRef = useRef(true);
      const busyRef = useRef(false);

      const [state, setState] = useState(null);
      const [firstLoad, setFirstLoad] = useState(true);
      const [loadError, setLoadError] = useState(null);
      const [actionError, setActionError] = useState(null);
      const [pending, setPending] = useState('');
      const [exportResult, setExportResult] = useState(null);

      /** 拉取一次 state；错误原样抛出，由调用方决定如何展示。 */
      const refresh = useCallback(async () => {
        const data = await readJson(API + '/state');
        if (mountedRef.current) {
          setState(data);
          setLoadError(null);
        }
        return data;
      }, []);

      // 首屏加载 + 15 秒轮询；卸载时清掉定时器。
      useEffect(() => {
        mountedRef.current = true;
        let cancelled = false;
        let timer = null;

        const tick = async (initial) => {
          try {
            await refresh();
          } catch (error) {
            const normalized = normalizeError(error);
            if (!cancelled && normalized.code !== 'aborted' && mountedRef.current) {
              setLoadError(normalized);
            }
          } finally {
            if (!cancelled) {
              if (initial) setFirstLoad(false);
              timer = setTimeout(() => tick(false), POLL_MS);
            }
          }
        };

        tick(true);
        return () => {
          cancelled = true;
          mountedRef.current = false;
          if (timer !== null) clearTimeout(timer);
        };
      }, [refresh]);

      const retry = async () => {
        setLoadError(null);
        setFirstLoad(true);
        try {
          await refresh();
        } catch (error) {
          if (mountedRef.current) setLoadError(normalizeError(error));
        } finally {
          if (mountedRef.current) setFirstLoad(false);
        }
      };

      /**
       * 提交一次配置变更：乐观更新 → POST → 用响应里的完整 state 覆盖。
       * 失败时回滚到提交前的快照并显示错误。
       */
      const runAction = async (key, body, optimistic) => {
        if (busyRef.current) return;
        busyRef.current = true;
        setPending(key);
        setActionError(null);
        const snapshot = state;
        try {
          if (typeof optimistic === 'function') optimistic();
          const data = await readJson(API + '/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });
          if (mountedRef.current) {
            if (data && (data.mode !== undefined || data.session !== undefined)) {
              setState(data);
              setLoadError(null);
            } else {
              await refresh();
            }
          }
        } catch (error) {
          const normalized = normalizeError(error);
          if (mountedRef.current) {
            setState(snapshot);
            setActionError(normalized);
          }
        } finally {
          busyRef.current = false;
          if (mountedRef.current) setPending('');
        }
      };

      const changeMode = (nextMode) => {
        if (nextMode === mode || busy) return;
        return runAction(
          'mode',
          { mode: nextMode },
          () => setState((current) => (current ? Object.assign({}, current, { mode: nextMode }) : current)),
        );
      };

      const togglePause = () => {
        const next = !paused;
        return runAction(
          'pause',
          { paused: next },
          () => setState((current) => (current ? Object.assign({}, current, { paused: next }) : current)),
        );
      };

      const toggleCategory = (category) => {
        if (busy) return;
        const nextValue = !categories[category];
        const nextMap = Object.assign({}, categories);
        nextMap[category] = nextValue;
        return runAction(
          'cat:' + category,
          // 只提交被改动的键：后端按 key 合并，工作区策略覆盖过的其它类别不受影响。
          { categories: { [category]: nextValue } },
          () => setState((current) => (current ? Object.assign({}, current, { categories: nextMap }) : current)),
        );
      };

      const exportCsv = async () => {
        if (busyRef.current) return;
        busyRef.current = true;
        setPending('export');
        setActionError(null);
        setExportResult(null);
        try {
          const data = await readJson(API + '/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}',
          });
          if (!mountedRef.current) return;
          const rows = Number(data && data.rows);
          const csv = data && typeof data.csv === 'string' ? data.csv : '';
          const filename = data && typeof data.filename === 'string' && data.filename ? data.filename : 'redact-audit.csv';
          const downloaded = csv.length > 0 ? downloadCsv(rootRef.current, filename, csv) : false;
          setExportResult({
            rows: Number.isFinite(rows) ? rows : 0,
            path: data && typeof data.path === 'string' ? data.path : '',
            downloaded,
            omitted: csv.length === 0,
          });
        } catch (error) {
          const normalized = normalizeError(error);
          if (mountedRef.current) setActionError(normalized);
        } finally {
          busyRef.current = false;
          if (mountedRef.current) setPending('');
        }
      };

      /* ---------------------------- 派生值 ---------------------------- */

      const mode = state && typeof state.mode === 'string' ? state.mode : 'off';
      const paused = Boolean(state && state.paused);
      const categories = (state && state.categories) || {};
      const session = (state && state.session) || {};
      const totals = (state && state.totals) || {};
      const byCategory = (session && session.byCategory) || {};
      const recent = state && Array.isArray(state.recent) ? state.recent.slice(0, MAX_RECENT) : [];
      const workspace = state && state.workspace ? state.workspace : null;
      const workspaceList = state && Array.isArray(state.workspaces) ? state.workspaces : [];
      const paths = (state && state.paths) || {};
      const busy = pending !== '';

      const catLabel = (category) => {
        const key = 'cat.' + category;
        const text = t(key);
        return text === key ? String(category || '') : text;
      };
      const catHint = (category) => t('cat.' + category + '.hint');
      const policyLabel = (policy) => {
        if (!policy) return '—';
        const key = 'policy.' + policy;
        const text = t(key);
        return text === key ? String(policy) : text;
      };
      const policyTone = (policy) => {
        if (policy === 'enforce') return 'success';
        if (policy === 'audit') return 'business';
        return 'idle';
      };
      const directionLabel = (direction) => {
        if (!direction) return '';
        const key = 'recent.direction.' + direction;
        const text = t(key);
        return text === key ? String(direction) : text;
      };

      const catKeys = CATEGORIES.filter((category) => byCategory[category] > 0);
      Object.keys(byCategory).forEach((category) => {
        if (catKeys.indexOf(category) < 0 && byCategory[category] > 0) catKeys.push(category);
      });

      const lastAt = totals.lastAt || (recent.length > 0 ? recent[0].ts : 0);
      const pausedUntil = Number(state && state.pausedUntil);
      const pausedHint = paused
        ? Number.isFinite(pausedUntil) && pausedUntil > 0
          ? t('mode.pausedUntil', { time: formatTime(pausedUntil, t) })
          : t('mode.pausedHint')
        : t('mode.pauseHint');

      const error = actionError || loadError;
      let errorText = '';
      if (error) {
        if (error.code === 'auth') errorText = t('error.auth');
        else if (error.code === 'network') errorText = t('error.network');
        else if (error.code === 'http' || error.code === 'server') {
          errorText = t('error.http', { status: error.status ? String(error.status) : '—' });
        } else errorText = t('error.unknown');
      }

      /* ---------------------------- 片段 ---------------------------- */

      const head = h(
        'div',
        { className: 'rgw-head' },
        h(
          'div',
          { className: 'rgw-headrow' },
          h('h2', { className: 'rgw-title' }, t('nav')),
          h(Badge, { tone: mode === 'enforce' ? 'success' : mode === 'audit' ? 'business' : 'idle' }, t('mode.' + mode)),
          paused ? h(Badge, { tone: 'warn' }, t('mode.pausedBadge')) : null,
        ),
        h('p', { className: 'rgw-intro' }, t('intro')),
      );

      const errorBar = error
        ? h(
            'div',
            { className: 'rgw-error', role: 'alert' },
            h(
              'div',
              { className: 'rgw-error-body' },
              h('div', null, errorText),
              error.detail ? h('div', { className: 'rgw-error-detail' }, String(error.detail).slice(0, 240)) : null,
            ),
            h(
              'button',
              {
                type: 'button',
                className: 'rgw-btn',
                onClick: error === loadError ? retry : () => setActionError(null),
              },
              error === loadError ? t('error.retry') : t('common.dismiss'),
            ),
          )
        : null;

      const skeleton =
        firstLoad && !state && !error
          ? h(
              React.Fragment,
              null,
              h('div', { className: 'rgw-skel', style: { height: '88px' } }),
              h(
                'div',
                { className: 'rgw-grid' },
                [0, 1, 2].map((index) =>
                  h('div', { key: index, className: 'rgw-skel', style: { height: '62px' } }),
                ),
              ),
              h('div', { className: 'rgw-skel', style: { height: '180px' } }),
            )
          : null;

      const statusBlock = state
        ? h(
            Section,
            { title: t('status.title'), hint: t('status.hint') },
            h(
              'div',
              { className: 'rgw-grid' },
              h(Stat, {
                label: t('stat.sessionPlaceholders'),
                value: formatCount(session.placeholders),
              }),
              h(Stat, {
                label: t('stat.sessionRequests'),
                value: formatCount(session.requests),
              }),
              h(Stat, {
                label: t('stat.totalPlaceholders'),
                value: formatCount(totals.placeholders),
              }),
              h(Stat, {
                label: t('stat.totalRequests'),
                value: formatCount(totals.requests),
              }),
              h(Stat, {
                label: t('stat.blocked'),
                value: formatCount(totals.blocked),
              }),
              h(Stat, {
                label: t('stat.lastAt'),
                value: lastAt ? formatTime(lastAt, t) : t('status.never'),
                small: true,
              }),
            ),
            h(
              'div',
              { className: 'rgw-card' },
              catKeys.length > 0
                ? h(
                    'div',
                    { className: 'rgw-chips' },
                    catKeys.map((category) =>
                      h(
                        'span',
                        { key: category, className: 'rgw-chip' },
                        catLabel(category),
                        h('strong', null, formatCount(byCategory[category])),
                      ),
                    ),
                  )
                : h('div', { className: 'rgw-empty' }, t('stat.none')),
            ),
          )
        : null;

      const modeBlock = state
        ? h(
            Section,
            { title: t('mode.title'), hint: t('mode.hint') },
            h(
              'div',
              { className: 'rgw-card' },
              h(
                'div',
                { className: 'rgw-row' },
                h(
                  'div',
                  { className: 'rgw-row-text' },
                  h('span', { className: 'rgw-row-label' }, t('mode.segLabel')),
                  h('span', { className: 'rgw-row-desc' }, t('mode.' + mode + '.hint')),
                ),
                h(
                  'div',
                  { className: 'rgw-seg', role: 'group', 'aria-label': t('mode.title') },
                  MODES.map((candidate) =>
                    h(
                      'button',
                      {
                        key: candidate,
                        type: 'button',
                        className: 'rgw-seg-btn',
                        'aria-pressed': mode === candidate ? 'true' : 'false',
                        disabled: busy,
                        onClick: () => changeMode(candidate),
                      },
                      t('mode.' + candidate),
                    ),
                  ),
                ),
              ),
              h(
                Row,
                { label: t('mode.pauseTitle'), desc: pausedHint },
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'rgw-btn' + (paused ? ' rgw-btn-warn' : ''),
                    disabled: busy,
                    onClick: togglePause,
                  },
                  pending === 'pause' ? t('mode.working') : paused ? t('mode.resume') : t('mode.pause'),
                ),
              ),
            ),
          )
        : null;

      const categoriesBlock = state
        ? h(
            Section,
            { title: t('cat.title'), hint: t('cat.hint') },
            h(
              'div',
              { className: 'rgw-card' },
              CATEGORIES.map((category) =>
                h(
                  Row,
                  { key: category, label: catLabel(category), desc: catHint(category) },
                  h(Switch, {
                    checked: Boolean(categories[category]),
                    disabled: busy,
                    label: catLabel(category),
                    onChange: () => toggleCategory(category),
                  }),
                ),
              ),
            ),
          )
        : null;

      const workspacesTable =
        workspaceList.length > 0
          ? h(
              'div',
              { className: 'rgw-card rgw-table-wrap' },
              h(
                'table',
                { className: 'rgw-table' },
                h(
                  'thead',
                  null,
                  h(
                    'tr',
                    null,
                    h('th', null, t('workspace.col.path')),
                    h('th', null, t('workspace.col.policy')),
                    h('th', null, t('workspace.col.matched')),
                  ),
                ),
                h(
                  'tbody',
                  null,
                  workspaceList.map((entry, index) =>
                    h(
                      'tr',
                      { key: (entry && entry.path) || index },
                      h(
                        'td',
                        null,
                        h('span', { className: 'rgw-mono rgw-path' }, (entry && entry.path) || '—'),
                        entry && entry.active
                          ? h('span', { className: 'rgw-tag rgw-tag-active' }, t('workspace.active'))
                          : null,
                      ),
                      h('td', null, h(Badge, { tone: policyTone(entry && entry.policy) }, policyLabel(entry && entry.policy))),
                      h('td', null, h('span', { className: 'rgw-mono rgw-path' }, (entry && entry.matched) || '—')),
                    ),
                  ),
                ),
              ),
            )
          : h('div', { className: 'rgw-card' }, h('div', { className: 'rgw-empty' }, t('workspace.empty')));

      const workspaceBlock = state
        ? h(
            Section,
            { title: t('workspace.title'), hint: t('workspace.hint') },
            h(
              'div',
              { className: 'rgw-card' },
              h(
                Row,
                { label: t('workspace.current') },
                h('span', { className: 'rgw-mono rgw-path', style: { maxWidth: '380px' } }, (workspace && workspace.path) || '—'),
              ),
              h(
                Row,
                { label: t('workspace.policy') },
                h(Badge, { tone: policyTone(workspace && workspace.policy) }, policyLabel(workspace && workspace.policy)),
              ),
              h(
                Row,
                { label: t('workspace.matched') },
                h('span', { className: 'rgw-mono rgw-path', style: { maxWidth: '380px' } }, (workspace && workspace.matched) || '—'),
              ),
            ),
            workspacesTable,
          )
        : null;

      const recentBlock = state
        ? h(
            Section,
            { title: t('recent.title'), hint: t('recent.hint') },
            h(
              'div',
              { className: 'rgw-card rgw-table-wrap' },
              recent.length > 0
                ? h(
                    'table',
                    { className: 'rgw-table' },
                    h(
                      'thead',
                      null,
                      h(
                        'tr',
                        null,
                        h('th', null, t('recent.time')),
                        h('th', null, t('recent.category')),
                        h('th', null, t('recent.mask')),
                        h('th', null, t('recent.placeholder')),
                        h('th', null, t('recent.session')),
                      ),
                    ),
                    h(
                      'tbody',
                      null,
                      recent.map((entry, index) =>
                        h(
                          'tr',
                          { key: (entry && entry.ts) + ':' + index },
                          h('td', { className: 'rgw-nowrap rgw-dim' }, formatTime(entry && entry.ts, t)),
                          h(
                            'td',
                            { className: 'rgw-nowrap' },
                            h('span', { className: 'rgw-tag' }, catLabel(entry && entry.category)),
                            entry && entry.direction
                              ? h('span', { className: 'rgw-tag' }, directionLabel(entry.direction))
                              : null,
                          ),
                          h('td', { className: 'rgw-mono' }, (entry && entry.mask) || '—'),
                          h('td', { className: 'rgw-mono rgw-accent' }, (entry && entry.placeholder) || '—'),
                          h('td', { className: 'rgw-mono rgw-dim rgw-clip' }, (entry && entry.sessionId) || '—'),
                        ),
                      ),
                    ),
                  )
                : h('div', { className: 'rgw-empty' }, t('recent.empty')),
            ),
          )
        : null;

      const exportBlock = state
        ? h(
            Section,
            { title: t('export.title'), hint: t('export.hint') },
            h(
              'div',
              { className: 'rgw-card' },
              h(
                'div',
                { className: 'rgw-row' },
                h(
                  'div',
                  { className: 'rgw-row-text' },
                  h('span', { className: 'rgw-row-label' }, t('export.button')),
                ),
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'rgw-btn rgw-btn-primary',
                    disabled: busy,
                    onClick: exportCsv,
                  },
                  pending === 'export' ? t('export.busy') : t('export.button'),
                ),
              ),
              exportResult
                ? h(
                    'div',
                    { className: 'rgw-empty', role: 'status', style: { paddingTop: '0' } },
                    h('div', null, t('export.done', { rows: formatCount(exportResult.rows) })),
                    exportResult.omitted ? h('div', null, t('export.tooLarge')) : null,
                    exportResult.path
                      ? h(
                          'div',
                          null,
                          t('export.path') + ': ',
                          h('span', { className: 'rgw-mono rgw-path' }, exportResult.path),
                        )
                      : null,
                  )
                : null,
            ),
          )
        : null;

      const footer = state
        ? h(
            'footer',
            { className: 'rgw-footer' },
            paths.dataDir
              ? h(
                  'div',
                  { className: 'rgw-footer-row' },
                  h('span', { className: 'rgw-footer-key' }, t('footer.dataDir')),
                  h('span', { className: 'rgw-footer-val rgw-mono' }, paths.dataDir),
                )
              : null,
            paths.auditDir
              ? h(
                  'div',
                  { className: 'rgw-footer-row' },
                  h('span', { className: 'rgw-footer-key' }, t('footer.auditDir')),
                  h('span', { className: 'rgw-footer-val rgw-mono' }, paths.auditDir),
                )
              : null,
            paths.vaultDir
              ? h(
                  'div',
                  { className: 'rgw-footer-row' },
                  h('span', { className: 'rgw-footer-key' }, t('footer.vaultDir')),
                  h('span', { className: 'rgw-footer-val rgw-mono' }, paths.vaultDir),
                )
              : null,
            h(
              'div',
              { className: 'rgw-footer-row' },
              h('span', { className: 'rgw-footer-key' }, t('footer.key')),
              h(
                'span',
                { className: 'rgw-footer-val' },
                t('footer.keyValue', { file: paths.keyFile || 'master.key' }),
                paths.keySource
                  ? h('span', { className: 'rgw-mono' }, ' · ' + paths.keySource)
                  : null,
              ),
            ),
            state.onError
              ? h(
                  'div',
                  { className: 'rgw-footer-row' },
                  h('span', { className: 'rgw-footer-key' }, t('footer.onError')),
                  h(
                    'span',
                    { className: 'rgw-footer-val' },
                    state.onError === 'pass' ? t('errorPolicy.pass') : t('errorPolicy.block'),
                  ),
                )
              : null,
            h(
              'details',
              { className: 'rgw-details' },
              h('summary', { className: 'rgw-summary' }, t('footer.how')),
              h(
                'ol',
                { className: 'rgw-how' },
                h('li', null, t('footer.how1')),
                h('li', null, t('footer.how2')),
                h('li', null, t('footer.how3')),
              ),
            ),
          )
        : null;

      return h(
        'div',
        {
          className: 'rgw-root',
          ref: rootRef,
          'aria-busy': busy || firstLoad ? 'true' : 'false',
        },
        h('style', { key: 'rgw-style' }, CSS),
        head,
        errorBar,
        skeleton,
        statusBlock,
        modeBlock,
        categoriesBlock,
        workspaceBlock,
        recentBlock,
        exportBlock,
        footer,
      );
    }

    /* ------------------------------------------------------------------ *
     * 注册
     * ------------------------------------------------------------------ */

    /**
     * Render-gap guard: a throwing page blanks its whole slot with no message,
     * which is indistinguishable from "the plugin did not load". This catches
     * the render and shows the error instead, so the failure is diagnosable
     * from the page itself.
     */
    class Boundary extends React.Component {
      constructor(props) {
        super(props);
        this.state = { error: null };
      }

      static getDerivedStateFromError(error) {
        return { error };
      }

      componentDidCatch(error) {
        // eslint-disable-next-line no-console
        console.error('dsh-redact-gateway: settings page crashed', error);
      }

      render() {
        if (this.state.error === null) return this.props.children;
        const t = this.props.t || ((key) => key);
        return h(
          'div',
          { style: { padding: '24px', fontFamily: 'inherit' }, role: 'alert' },
          h('div', { style: { fontWeight: 600, marginBottom: '8px' } }, t('error.title')),
          h(
            'pre',
            {
              style: {
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontSize: '12px',
                margin: 0,
                opacity: 0.8,
              },
            },
            String(this.state.error && this.state.error.stack ? this.state.error.stack : this.state.error),
          ),
        );
      }
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        ctx.effect(
          () => ctx.locale.register(NS, { en: EN, zh: ZH }),
          'dsh-redact-gateway: dictionaries',
        );

        const t = ctx.locale.bind(NS);

        ctx.effect(
          () =>
            ctx.slots.inject('settings.section', () =>
              ctx.slots.register(
                {
                  name: 'settings.section',
                  id: SECTION_ID,
                  order: 90,
                  label: () => t('nav'),
                  locale: NS,
                  inject: () => ({ t }),
                },
                (ownerProps) => h(Boundary, { t }, h(Page, Object.assign({}, ownerProps, { t }))),
              ),
            ),
          'dsh-redact-gateway: settings section',
        );

        ctx.effect(
          () =>
            ctx.slots.inject('settings.section.icon', () =>
              ctx.slots.register(
                {
                  name: 'settings.section.icon',
                  id: SECTION_ID,
                  order: 90,
                  locale: NS,
                },
                (ownerProps) => h(SectionIcon, ownerProps),
              ),
            ),
          'dsh-redact-gateway: settings section icon',
        );
      },
    };
  },
});
