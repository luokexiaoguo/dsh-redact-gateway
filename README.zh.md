# 出网脱敏网关（dsh-redact-gateway）

[English](README.md) | 中文

> DSH 会把提示词、工具返回和附件**原样**发给模型服务商。这个插件在请求离开本机之前拦住它，
> 把身份证、手机号、银行卡、邮箱、地址、客户名及密钥换成编号占位符，响应回来再自动回填。
> 用户看到的是原文，模型全程没见过原文。

面向"要把内部文档、代码和客户资料交给云端模型，但安全评审第一关就卡在数据出域"的团队。
和"给模型一个需要主动调用的脱敏工具"不同，这里是**在传输边界上强制生效**的：模型没有选择权，
也没有"忘了调"这种失败模式。

---

## 1. 它到底做了什么

```
会话日志（原文，用户看到的就是它）
        │  deriveMessages()
        ▼
  冻结的请求 ──► llm/stream 拦截 ──► 检测 + 替换 ──► 审计 ──► 映射表加密落盘
                                        │
                                        ▼
                              模型服务商（只看到 [EMAIL_1]）
                                        │
                                        ▼
                              流式回填（占位符 → 原文）
                                        │
                                        ▼
                          助手消息写入会话日志（原文） ──► 用户看到原文
```

三个关键性质：

1. **模型侧不可绕过。** 拦截点在 `llm/stream` 瀑布，而不是"某个工具"。任何模型调用
   （主对话、子代理、会话标题、上下文压缩）都经过它。
2. **用户侧无损。** 会话日志保存的是原文，占位符只存在于出网的那一份拷贝里。
   所以回填不需要"猜"，也不需要修改历史。
3. **可审计。** 每次替换写一行审计记录，含类别、规则、占位符、部分掩码、加盐指纹和哈希链。
   一条 `record_hash` 链起来，删改一行就会在 `verify` 时暴露。

### 为什么不是"匿名化"

**这是去标识化（pseudonymisation），不是匿名化（anonymisation）。** 占位符是可逆的，
映射表保存在本机，所以按《个人信息保护法》第 73 条的定义，它不构成"匿名化"，映射表本身仍是
个人信息，仍在 PIPL 的适用范围里。本插件提供的是第 51 条要求的技术措施（加密、去标识化、
访问控制），**不是**"处理个人信息后就不再是个人信息"的豁免。请勿在评审材料里把它写成匿名化。

---

## 2. 安装

```bash
# 已发布到 npm（推荐）—— https://www.npmjs.com/package/dsh-redact-gateway
#   plugin_manager action=install_bundle target=dsh-redact-gateway

# 目录安装（开发/内网分发）
#   npm install            # 或者 clone 仓库
#   plugin_manager action=install_bundle target=<包的绝对路径>
```

装好后在 **设置 → 出网脱敏网关** 打开页面，可以看状态、切换模式、按类别开关、导出审计 CSV。
插件行本身的配置在 profile 的 `cordis.patch.yml` 里（见第 5 节）。

> 首次安装后请发一条含测试数据的消息（例如一个虚构手机号），确认设置页里的计数增加。
> 计数不动说明拦截没有生效，先排查配置再投入使用。

---

## 3. 识别哪些东西

| 类别 | 占位符 | 校验方式 | 主要误报风险 |
| --- | --- | --- | --- |
| `secret` 密钥 | `[SECRET_1]` | 厂商前缀 + 熵 + 关键词邻近 | 哈希/UUID 被误判（已内置 allowlist） |
| `idcard` 身份证 | `[IDCARD_1]` | GB 11643 ISO 7064 MOD 11-2 + 真实日期 + 行政区划 | 18 位订单号 |
| `bankcard` 银行卡 | `[BANKCARD_1]` | Luhn + 主流 IIN 段 | Luhn 合法的订单号/IMEI |
| `phone` 手机/座机 | `[PHONE_1]` | 号段 + 边界 | 少 |
| `email` 邮箱 | `[EMAIL_1]` | 实用正则 + 结构校验 | 少 |
| `address` 地址 | `[ADDR_1]` | 省市区 + 道路 + 门牌 复合匹配 | 法律/新闻文本里的地址 |
| `name` 人名 | `[NAME_1]` | 姓氏表 + 上下文锚定（默认严格） | 裸匹配会把"张总"当人名（已默认关闭） |
| `org` 机构/客户名 | `[ORG_1]` | 统一社会信用代码 GB 32100 校验 + 名称后缀 | 通用词（"建设""东方"） |
| `custom` 自定义词典 | `[TERM_1]` | 字面量，最长匹配 | 短词误伤 |

**优先级与重叠**：`secret > custom > idcard > bankcard > phone > email > org > address > name`。
身份证里的 11 位数字不会被同时当成手机号。

**自定义词典是投入产出比最高的开关。** 把客户名单、项目代号、内部产品名放进
`dictionary`（或让模型用 `redact_dictionary` 工具加），比指望人名/机构名的启发式规则可靠得多。

### 占位符格式

默认 `[EMAIL_1]`——单个方括号、大写类别、下划线、递增编号。这是实测里最容易让模型原样复述的
形状：模型会自己把 `<Name_1>` 改写成 `[Name_1]`，而 `[[…]]` 会和 wiki 链接语法冲突。

回填是**宽容**的：`[[EMAIL_1]]`、`[ email - 1 ]`、`［EMAIL_1］`、`(EMAIL_1)`、`{EMAIL_1}`
都能还原，并会计入"修复次数"。模型**自己编出来**的占位符（例如从没发过的 `[ORG_9]`）不会被
猜测——原样保留并计入未知计数，这是唯一安全的处理方式。

---

## 4. 工作区白名单与豁免

按会话的工作目录做**最长前缀**匹配，所以可以在一个被豁免的目录里再给某个子目录重新开启。

```yaml
workspaces:
  # 公开资料目录：完全不处理，也不写审计
  - path: 'D:/work/public-docs'
    policy: bypass

  # 被豁免目录里的敏感子目录：重新强制
  - path: 'D:/work/public-docs/payroll'
    policy: enforce
    dictionary: ['薪级表', '调薪方案']

  # 只记录不替换（灰度期用）
  - path: 'D:/work/legacy-crm'
    policy: audit
```

`policy` 取值：`enforce`（默认，替换）/ `audit`（只记录不替换）/ `bypass`（完全跳过）。
`bypass` 连审计都不写，用于确有把握的公开目录；`audit` 是"先看清有多少数据会流动"的灰度模式。

---

## 5. 配置参考

```yaml
- id: redact-gateway
  name: dsh-redact-gateway
  config:
    mode: enforce              # enforce | audit | off
    onError: block             # block | pass（见第 8 节）

    categories:                # 全局类别开关
      name: false              # 人名启发式误报多时关掉它
      address: true

    dictionary: []             # 自定义敏感词
    allowlist:
      values:                  # 永不脱敏的字面量
        - 'example.com'
        - '13800000000'
      patterns:                # 永不脱敏的正则
        - '@example\.(com|org)$'

    minCustomLength: 2
    nameStrict: true           # 人名只在上下文锚定时命中
    promptHint: true           # 向系统提示追加"占位符原样保留"的说明
    streamRehydrate: true      # 流式回填（关掉则只在块结束时回填）
    vaultTtlHours: 168         # 会话映射表保留时长

    workspaces: []             # 见第 4 节
    dir: ''                    # 数据目录，默认 <DSH_HOME>/redact-gateway

    audit:
      retentionDays: 90
      mask: true               # 审计里是否写部分掩码
      dedupe: true             # 同一会话内同一值只记一行（长对话每轮都会重发历史）
      dir: ''                  # 默认 <数据目录>/audit
```

设置页上的改动先在进程内生效，随后会写回 profile 配置（写回会重启插件，属正常现象）。

---

## 6. 数据落在哪里

```
<DSH_HOME>/redact-gateway/
├── master.key                      # 32 字节 AES 主密钥（0600）
├── fingerprint.key                 # 审计指纹 HMAC 密钥（0600，与主密钥分离）
├── sessions/<sessionId>.vault      # AES-256-GCM 加密的占位符映射
├── audit/YYYY-MM.jsonl             # 追加式审计，带哈希链
├── audit/stats.json                # 累计计数
└── exports/redact-audit-*.csv      # 导出的 CSV
```

**两把密钥是刻意的设计**：`master.key` 能解开映射（可逆），`fingerprint.key` 只能算不可逆指纹。
导出的 CSV 只含后者，所以可以安全地在公司内部邮件里传阅——拿到 CSV 也推不出原文。

**为什么审计不用"盐 + 哈希"**：手机号空间只有几十亿，一张显卡几秒就能穷举；身份证空间约
10¹¹，几分钟。加盐哈希在脱敏场景里等于没脱敏。这里用**带密钥的 HMAC**，没有密钥就无法穷举。

**密钥轮换**：设置 `DSH_REDACT_KEY`（32 字节 base64/hex）可覆盖 `master.key`，便于统一托管。
换掉密钥后旧映射表无法解密（会被改名保留为 `*.vault.unreadable-<ts>`，不删除），
会话内已发出的占位符只能保留原样。请在会话边界操作。

---

## 7. 审计 CSV

列（21 列，UTF-8 BOM，Excel 可直接打开）：

```
seq, timestamp_utc, timestamp_local, session_id, workspace_fp, provider, model, purpose,
direction, action, category, rule_id, placeholder, mask, value_fp, value_shape,
validation, occurrences, outcome, prev_hash, record_hash
```

- **绝不包含原文**，也不包含文件名、提示词正文。
- `workspace_fp` 是工作区路径的 HMAC：安全团队能判断"是不是同一个项目"，但 CSV 泄露不会暴露项目名。
- `value_fp` 是值的 HMAC 前 128 位：跨记录关联同一个身份证，但不可反推。
- `mask` 形如 `138*****111`：足以让评审者认出来是什么类型的数据，不足以复用。
- 已做 **CSV 公式注入**防护（以 `=` `+` `-` `@` 等开头的单元格会加 `'` 前缀并整体加引号）。
- **默认按"同一会话同一值只记一行"去重**（`audit.dedupe`）。原因：长对话每一轮都会把整段历史重新发给模型，
  逐次记录会把 70 个不同的敏感项变成近千行完全重复的记录。去重后 `occurrences` 仍然给出真实出现次数；
  需要逐次取证时把它设为 `false`。

导出方式：设置页按钮、`/redact export [天数]`、或 `redact_export_csv` 工具。
校验完整性：`/redact verify`，会重算整条哈希链并报告第一个断裂位置。

---

## 8. 失败策略：为什么默认是"拦下来"

脱敏流程本身出错时（磁盘写不了、加密失败、检测器抛异常），默认 `onError: block`：
**本次请求直接失败，原文一个字都不发出去**，错误信息里写明是网关拦的。

这是安全产品的正确默认——"保护失效时数据照常出网"等于没有保护。代价是极少数情况下你会看到
一条看不懂的报错。排查手段：看 DSH 日志里的 `redact-gateway:` 前缀；临时把 `onError` 改成
`pass` 可以让请求通过（会在审计里留下 `action=block`/`outcome=allowed` 之外的可追溯痕迹），
但请把改回去当成必须完成的动作。

另一个强制点是**映射表落盘**：如果映射写不进磁盘，请求同样会被拦。原因很直接——占位符发出去
了、映射丢了，响应就再也回填不回来，用户会看到一堆 `[EMAIL_1]`。

---

## 9. 工具与命令

给模型的工具（**返回给模型的内容永不含原文**）：

| 工具 | 用途 |
| --- | --- |
| `redact_status` | 模式、工作区策略、类别开关、本会话计数 |
| `redact_preview` | 给一段文本，返回"会替换哪些跨度"（只有类别/规则/占位符/偏移，**没有匹配到的值**） |
| `redact_audit` | 读最近的审计行（掩码 + 指纹） |
| `redact_export_csv` | 导出 CSV 并返回路径 |
| `redact_dictionary` | 列出/新增/删除自定义敏感词 |

给用户的斜杠命令：

```
/redact                    状态
/redact pause [分钟]       临时暂停（默认 30 分钟），期间审计记 pause-skip
/redact resume             恢复
/redact export [天数]      导出最近 N 天审计
/redact verify             校验哈希链
```

暂停是**用户专属**操作：模型没有工具能暂停保护，这是刻意的。

---

## 10. 已知边界（请如实告知评审方）

- **只处理文本。** 图片/附件字节仍会出网；DSH 已把文件引用替换成句柄文本，但图片里的文字
  （截图、扫描件）不在本插件范围内。需要时请用工作区 `bypass` 之外的手段限制图片上传。
- **工具调用的流式参数不实时回填。** JSON 片段中途替换会破坏引号，所以占位符在块结束时
  一次性回填；工具执行拿到的仍是原文，但流式预览的那一瞬间可能看到占位符。
- **人名/地址是启发式。** 有漏报也有误报。生产环境请以自定义词典为主、启发式为辅，并按工作区调类别开关。
- **模型会改写占位符。** 这是实测出来的失败模式，不是 bug：模型可能换括号、加空格、改名、
  甚至编造占位符。本插件能修的就修（计入 `repair`），修不了的保持原样并计数。
  `promptHint` 能显著改善，但不能消除。
- **两个网关不叠加。** 如果组织里另有出口网关，本插件应当配置为 `audit` 模式做数据可视，
  而不是两层都做替换（否则占位符会互相踩）。
- **`verify` 类能力本身就是一次出网。** 本插件不做"把密钥拿去校验有效性"的动作。

---

## 11. 合规对照

| 要求 | 本插件的对应措施 |
| --- | --- |
| PIPL 第 51 条 加密 / 去标识化 / 访问控制 | 映射表 AES-256-GCM + AAD 绑定会话；审计只存 HMAC |
| PIPL 第 47 条 删除权 | 会话映射表 TTL（`vaultTtlHours`）+ 删除文件即"加密粉碎" |
| PIPL 第 55/56 条 出境/对外提供 的告知与影响评估 | 审计 CSV 即处理记录，含时间、类别、工作区指纹、模型与提供商 |
| PIPL 第 73 条 去标识化 vs 匿名化 | 明确声明为**去标识化**，映射表按个人信息管理 |
| GDPR 第 30 条 处理活动记录 | CSV 覆盖类别、接收方（provider/model）、时间、删除期限 |
| GDPR 第 32 条 假名化作为安全措施 | 占位符 + 分离密钥 + 审计链 |

留存建议：审计热存 90 天、归档 3 年（PIPL 第 56 条影响评估记录的下限）。
映射表默认 7 天后清理——它只服务于在线会话回填，没有长期保留的必要，越短越安全。

---

## 12. 目录结构

```
index.js            # apply()：装配与生命周期
lib/config.js       # 配置规范化、工作区策略解析
lib/rules.js        # 检测引擎（纯函数，可单独测试）
lib/redact.js       # 请求脱敏（不可变重建）
lib/stream.js       # 流式回填（跨 chunk 占位符、宽容匹配、修复计数）
lib/vault.js        # AES-256-GCM 会话映射表
lib/audit.js        # 审计日志、哈希链、CSV 导出
lib/gateway.js      # llm/stream 编排与失败策略
lib/http.js         # 设置页后端路由（同源 + 连接服务双重校验）
lib/tools.js        # 模型工具
client/client.js    # 设置页 Web UI
test/               # node:test 单元测试（node test/xxx.test.mjs）
```

## 13. 开发与验证

```bash
cd packages/redact-gateway
node test/units.test.mjs       # 配置 / 映射表 / 回填 / 审计
node test/rules.test.mjs       # 检测规则
```

> 在受限沙箱里请直接 `node <file>`，不要用 `node --test`（后者会 spawn 子进程，被沙箱拦成 EPERM）。
