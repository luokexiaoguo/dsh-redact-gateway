# 出网脱敏网关 — 设计与接口规格

> 状态：实现中 v1.0。本文件同时是给协作者的接口契约，改动需同步 README。

## 1. 问题

DSH 把提示词、工具返回、附件原样发给模型服务商。企业安全评审的第一道关卡是"数据出域"。
现有方案只有一个"需要模型主动调用"的脱敏工具：忘了调就漏，且无留痕。

本插件在**请求出网前自动拦截**（`llm/stream` 与工具边界），本地规则 + 词典识别敏感数据，
替换为编号占位符，映射表加密存本机；响应回来自动回填；每次替换写审计日志，可导出 CSV。

## 2. 关键架构事实（已用源码核实）

| 事实 | 结论 |
| --- | --- |
| `llm/stream` 的 `options` 由 agent-loop `Object.freeze` + messages `deepFreeze` | **不能原地改写**请求，必须自己重新分发 |
| `ctx.on('llm/stream', (options, next) => AsyncIterable)` | 监听器必须同步返回 AsyncIterable |
| `ctx.llm.prepareCall(config)` → `{ stream(options) }`，`stream()` 仍走 `llm/stream` 瀑布 | 需要一个 WeakSet 递归守卫（深度 2 后 `next()`） |
| `PreparedLlmCall.stream()` 一次性（`INVALID_PREPARED_CALL`）且校验 `callConfigEquals` | 每次分发新建 handle，且必须原样传 provider/model/reasoningEffort/temperature/maxTokens/stop |
| 请求里没有 `system` 字段，系统提示是 messages 里的 `role:'system'` 消息 | 只处理 messages 即可 |
| `ToolCallBlock.arguments` 是 JSON 字符串；`BlockAssembler` 以 `block-end.block` 为准 | 在 `block-end` 回填 tool-call 参数即可让工具拿到原文，无需改写 `tools/execute` |
| `session.deriveMessages()` 是请求来源，durable 日志保存原文 | 用户看到的 = 原文；模型看到的 = 占位符，两者天然分离 |
| `Session.header.cwd` 存在；`llm/stream` 的 `options.sessionId` 给出会话 | 工作区 = cwd 前缀匹配 |

### 数据流

```
session log (原文)  ──deriveMessages──▶ frozen request
                                          │
                    ┌─────────────────────┴──────────────────┐
                    │ llm/stream 插件监听器                   │
                    │  1. 解析工作区策略（enforce/audit/bypass）│
                    │  2. 检测 → 生成占位符 → 写审计           │
                    │  3. 重建 options（messages 脱敏副本）    │
                    │  4. ctx.llm.prepareCall().stream(new)   │
                    │  5. 回填 chunk（text/reasoning/block-end）│
                    └─────────────────────┬──────────────────┘
                                          ▼
                            模型服务商（只见 [EMAIL_1]）
```

## 3. 目录与模块

```
packages/redact-gateway/
  package.json          # dsh.bundle.patch + dsh.client
  cordis.patch.yml
  index.js              # apply()：装配、配置解析、生命周期
  lib/config.js         # 配置规范化 + 工作区策略解析（无第三方依赖）
  lib/rules.js          # 【协作者 A】检测引擎（纯函数）
  lib/vault.js          # AES-256-GCM 会话映射表
  lib/audit.js          # 追加式审计日志 + hash 链 + CSV
  lib/redact.js         # 请求 → 脱敏请求（纯函数，基于 rules+vault）
  lib/stream.js         # 流式回填器（跨 chunk 占位符拼接）
  lib/gateway.js        # llm/stream 编排、分发、失败策略、统计
  lib/http.js           # 设置页后端路由
  lib/tools.js          # 模型可调用工具
  client/client.js      # 【协作者 B】Web UI（settings.section）
  locale/{en,zh}.json
  icon.svg
  test/*.mjs
```

## 4. 模块契约

### 4.1 `lib/rules.js`（协作者 A）

纯函数、零依赖、可在 `node --test` 下直接跑。

```js
export const CATEGORIES = ['secret','idcard','bankcard','phone','email','address','name','org','custom'];

/**
 * @param {object} options
 * @param {Record<string, boolean>} options.categories  启用类别（缺省全开）
 * @param {string[]} options.dictionary                自定义词典（客户名/项目代号）
 * @param {string[]} options.allowlist                 永不脱敏的字面量
 * @param {string[]} options.allowPatterns             永不脱敏的正则源串
 * @param {number}  [options.minCustomLength=2]
 * @returns {{ detect(text: string): Detection[] }}
 */
export function createDetector(options)

/** @typedef {{start:number,end:number,value:string,category:string,ruleId:string}} Detection */
```

要求：
- 结果按 `start` 升序、**互不重叠**；重叠时优先级 `secret > custom > idcard > bankcard > phone > email > org > address > name`，同优先级取更长者。
- 允许列表命中（字面量或正则）的马赛克区间整体丢弃。
- 校验算法必须真实实现：身份证 GB11643 ISO 7064 MOD 11-2、银行卡 Luhn、手机号号段、日期合法性。
- 对 100 KB 中文文本，`detect()` 目标 < 120 ms（各规则正则在全文扫一遍即可，总计不超过 ~25 遍；随后做一次区间归并）。测试里放一个 perf 冒烟用例。
- 不得依赖 `RegExp.lastIndex` 的全局状态泄漏（每个 detector 实例自持正则）。
- 每个检测必须给稳定的 `ruleId`（如 `idcard.cn18.checksum`），供审计与规则豁免使用。

### 4.2 `lib/stream.js`

```js
export class Rehydrator {
  constructor({ resolve, open = '[[', close = ']]' })
  push(text)   // → string，可安全立即输出的部分（对齐占位符边界）
  flush()      // → string，剩余
}
```
跨 chunk 的 `[[EMA` / `IL_1]]` 必须能拼回；`[[` 后不匹配任何已知占位符时要能立刻放行（不能卡住 markdown 链接）。
宽容匹配：`[X_1]`、`[ X_1 ]`、全角括号都要能回填。

### 4.3 `lib/vault.js`

```js
export class Vault {
  static async open({ dir, sessionId, key })   // 读或建 <dir>/sessions/<sessionId>.vault
  placeholder(category, value)                 // 幂等：同值同占位符，计数 +1
  resolve(placeholder)                         // → value | undefined
  entries()                                    // [{category, index, placeholder, value, hits}]
  flush()                                      // 落盘（防抖）
  dispose()
}
```
- 文件格式：`JSON{ v, alg:'aes-256-gcm', iv, tag, data }`，`data` 是 base64(GCM(JSON))。
- 密钥：`<dir>/master.key`（32B，权限 0600），或环境变量 `DSH_REDACT_KEY`(base64/hex)。
- 占位符编号在会话内单调递增、**不回收**；同一值永远复用同一占位符。

### 4.4 `lib/audit.js`

```js
export class AuditLog {
  static async open({ dir, retentionDays, mask })
  record(entry)   // 追加 JSONL，写 hash 链 prev
  query({ since, until, category, sessionId, limit })
  exportCsv({ since, until, category, outPath })
  stats()
}
```
记录字段：`ts, seq, prev, sessionId, workspace, provider, model, purpose, direction, category, ruleId, placeholder, mask, sha256, length`。
**绝不写原文**；`mask` 形如 `138****8888`（可关）；`sha256` = sha256(salt + value) 前 16 hex，用于跨记录关联。

## 5. 配置（cordis.patch.yml 的 config）

```yaml
mode: enforce                 # enforce | audit | off
onError: block                # block | pass
workspaces:                   # 最长前缀匹配
  - path: 'D:/work/public'    # 绝对路径或 glob
    policy: bypass            # enforce | audit | bypass
  - path: 'D:/work/customer'
    categories: [secret, idcard, email, custom]
    dictionary: ['某某集团']
categories:                   # 覆盖全局类别开关
  name: false
dictionary: []
allowlist:
  values: ['example.com', '13800000000']
  patterns: ['@example\.(com|org)$']
placeholder: { open: '[', close: ']' }
promptHint: true              # 向系统提示追加"占位符保持原样"的说明
streamRehydrate: true         # 增量回填（关闭则只在 block-end 回填）
audit:
  retentionDays: 90
  mask: true
  dir: ''                     # 默认 <DSH_HOME>/redact-gateway
```

## 6. HTTP 契约（设置页）

前缀 `/dsh-redact-gateway`，全部 `exact` 路由；**同源校验 + `ctx.connection.requestRejection`**。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/state` | 见下 |
| POST | `/config` | 局部更新：`{mode?, paused?, categories?, dictionary?, allowlist?}` |
| POST | `/export` | `{since?, until?, category?}` → `{ok, path, filename, rows, csv}`（`csv` 供浏览器直接下载；超过 2 万行时 `csv` 为空、仅 `path`） |
| GET | `/audit?limit=&since=&category=` | 最近审计行 |

`GET /state` 返回：
```json
{
  "ok": true, "version": "1.0.0", "mode": "enforce", "paused": false, "onError": "block",
  "workspace": { "path": "D:/work/a", "policy": "enforce", "matched": "D:/work/a" },
  "categories": { "idcard": true, "phone": true, "...": true },
  "session": { "id": "session-3", "placeholders": 12, "requests": 4, "byCategory": {"email": 7} },
  "totals":  { "requests": 128, "placeholders": 940, "blocked": 0, "lastAt": 1730000000000 },
  "recent": [ { "ts": 0, "category": "email", "mask": "a***@b.com", "placeholder": "[EMAIL_1]", "sessionId": "session-3", "direction": "out" } ],
  "paths": { "dataDir": "...", "auditDir": "...", "vaultDir": "..." }
}
```

## 7. 工具 / 命令

模型工具（**返回给模型的内容永不含原文**）：
- `redact_status` — 状态与计数
- `redact_preview(text)` — 只返回 `[{category, placeholder, start, end}]` + 计数，无原文
- `redact_audit(limit, since, category)` — 掩码后的审计行
- `redact_export_csv(since, until, category)` — 导出并返回路径 + 行数
- `redact_dictionary(action, value)` — `list|add|remove` 自定义词典

用户命令 `/redact`：`status | pause [分钟] | resume | export [since]`（用户专属，模型不能授权）。

## 8. 失败与安全策略

- `onError: block`（默认）：脱敏流程任何异常 → 该请求返回终止 `finish` 错误块，绝不发出原文。
- 工作区 `bypass` → 完全跳过（连审计都不写），用于公开资料目录。
- 临时暂停（命令/UI）：全局 `paused` 到时间戳，审计记录 `action:'paused-skip'`。
- 密钥/映射文件权限：文件写入后 `chmod 0600`（Windows 上尽力而为并记录）。
- 占位符不可逆推断：审计只存掩码与加盐 hash。

## 9. 已知边界（写进 README）

- 图片/附件：DSH 已把文件替换为句柄文本；**图片字节**仍会出网，OCR 类泄露不在本插件范围（可配置 `blockImages` 后续版本）。
- `tool-call-delta` 的流式参数不实时回填（JSON 片段不安全），在 `block-end` 一次性回填，工具执行拿到的仍是原文。
- 人名/地址识别基于启发式（姓氏表 + 后缀 + 行政区划），有误报/漏报，需要按工作区调词典。

---

## 10. 实现记录（与设计稿的差异，以本节为准）

实现过程中有 6 处按实测/实机结论改掉了设计稿的初版决定，README 是与用户对齐的权威文档：

1. **占位符改成单方括号 `a@b.com`**（设计稿初版是 `a@b.com`）。依据：arXiv:2610.34012 的实测显示模型会自行把 `<Name_1>` 改写成 `项目代`，而 `[[…]]` 与 wiki 链接语法冲突。回填端因此做得**宽容**：接受 `[X_1]` / `[[X_1]]` / `[ x - 1 ]` / `［X_1］` / `(X_1)` / `{X_1}`，并统计"修复次数"；模型**编造**的占位符原样保留并计数，绝不猜测。
2. **审计指纹从"加盐 hash"改成"带密钥 HMAC"**（`fingerprint.key` 与 `master.key` 分离）。原因：手机号空间几十亿、身份证空间约 10¹¹，加盐哈希可被穷举，等于没脱敏。导出 CSV 只含 HMAC，可安全传阅。
3. **审计默认去重**（`audit.dedupe`）：长对话每轮重发全部历史，逐次记录会把 ~70 个不同敏感项放大成近千行重复记录；去重后每会话每值一行，`occurrences` 保留真实次数。
4. **可选服务改用 `ctx.inject([...], cb)` 获取**，不在 `apply` 里 `ctx.get()` 一次。`webServer` / `systemPrompt` / `commands` 都是异步服务，一次性读取会永久漏掉。
5. **插件必须只用命名导出**（`name` / `inject` / `apply`）。Loader 先取 `exports.default` 并**丢弃同级命名导出**，加了 `export default apply` 会让 `inject` 失效，激活时直接报 `cannot get property "tools" without inject`。
6. **`Detection` 增加 `shape` 字段**（`cn-id-18` / `cn-mobile` / `email` …），`validation` 单独表示校验方式；审计里 `value_shape` 与 `validation` 分列，否则无法回答"这个月多少命中是校验位不过的"。

另外两处工程约束：

- 工具 `output.schema` 必须是合法 JSON Schema 子集，`{ type: 'json' }` 会被拒（`schema.type must be one of object/array/...`），这里用 `{ type: 'object', additionalProperties: true }`。
- 沙箱内跑测试用 `node test/x.test.mjs`，`node --test` 会 spawn 子进程并被拦成 `EPERM`。
