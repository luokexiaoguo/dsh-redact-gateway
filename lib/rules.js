/**
 * redact-gateway 敏感信息检测引擎（DESIGN.md §4.1）
 *
 * 设计约束：
 *   - 纯 ESM、零第三方依赖、不 import 任何 node: 内置模块（只用 JS 语言本身）；
 *   - `detect()` 幂等、无跨调用状态（所有正则都在使用前后复位 lastIndex）；
 *   - 返回区间按 start 升序且**互不重叠**；
 *   - 每条检测都带稳定 ruleId + validation（审计要看“这条命中靠什么验证的”）。
 *
 * 整体流程（对全文各扫一遍，O(n) 级别）：
 *   1) 各规则扫描 → 候选区间（带 category / ruleId / validation / shape）
 *   2) allowlist 字面量 + allowPatterns 正则覆盖过滤；既有占位符 [[XXX_n]] 区间过滤
 *   3) 按优先级贪心归并（secret > custom > idcard > bankcard > phone > email > org > address > name，
 *      同级取更长者），用位图做 O(区间长度) 的重叠检测
 *   4) 排序输出
 *
 * 误报控制的总体思路：凡是**有校验算法**的类别（身份证、银行卡、统一社会信用代码）
 * 一律真算校验位，算不过直接丢弃 —— 这是最有效的降误报手段；
 * 没有校验算法的类别（地址、人名、公司名）靠“结构 token 共现”和“上下文锚定”压误报。
 */

export const CATEGORIES = ['secret', 'idcard', 'bankcard', 'phone', 'email', 'address', 'name', 'org', 'custom'];

/** 归一化优先级：数值越小越优先（同时决定 allowlist 之外的重叠胜负）。 */
const PRIORITY = Object.freeze({
  secret: 0,
  custom: 1,
  idcard: 2,
  bankcard: 3,
  phone: 4,
  email: 5,
  org: 6,
  address: 7,
  name: 8,
});

/* ══════════════════════════════════════════════════════════════════════════
 * 基础工具
 * ══════════════════════════════════════════════════════════════════════════ */

/** CJK 统一表意文字基本区（姓氏表/地址/公司名只认这一区）。 */
function isCjkCode(code) {
  return code >= 0x4e00 && code <= 0x9fa5;
}

/** ASCII 单词字符（用于自定义词典的词边界判断）。 */
function isAsciiWordCode(code) {
  return (
    (code >= 48 && code <= 57) || // 0-9
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    code === 95 // _
  );
}

/**
 * 香农熵（bits/char）。
 * 用于 generic secret 兜底规则：低熵串（1234567890 / aaaaaaaa）基本都是占位/示例值。
 */
function shannonEntropy(s) {
  if (!s) return 0;
  const counts = new Map();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    counts.set(c, (counts.get(c) || 0) + 1);
  }
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** 收集一个候选（内部结构，value 最后统一 slice，避免为丢弃的候选生成字符串）。 */
function pushHit(cands, start, end, category, ruleId, validation, shape) {
  if (!(end > start) || start < 0) return;
  cands.push({ start, end, category, ruleId, validation, shape });
}

/**
 * 整段匹配即一个检测（格式类规则）。
 * 传入的正则必须是 /g（会自动复位 lastIndex）。
 */
function pushMatchAll(cands, text, re, category, ruleId, validation, shape, adjust) {
  re.lastIndex = 0;
  let m;
  try {
    while ((m = re.exec(text)) !== null) {
      let start = m.index;
      let end = m.index + m[0].length;
      if (m[0].length === 0) {
        // 零长匹配：必须手动推进，否则死循环
        re.lastIndex = m.index + 1;
        continue;
      }
      if (adjust) {
        const r = adjust(start, end);
        if (!r) continue;
        start = r[0];
        end = r[1];
      }
      pushHit(cands, start, end, category, ruleId, validation, shape);
    }
  } finally {
    re.lastIndex = 0;
  }
}

/**
 * 只把第 group 个捕获组当作检测区间（例：连接串里的口令、.env 的值、Bearer token）。
 * 要求正则带 `d` 标志（hasIndices）才能取到捕获组的绝对位置。
 */
function pushCaptureAll(cands, text, re, category, ruleId, validation, shape, adjust) {
  re.lastIndex = 0;
  let m;
  try {
    while ((m = re.exec(text)) !== null) {
      if (m[0].length === 0) {
        re.lastIndex = m.index + 1;
        continue;
      }
      const idx = m.indices && m.indices[1];
      if (!idx) continue;
      let start = idx[0];
      let end = idx[1];
      if (adjust) {
        const r = adjust(start, end);
        if (!r) continue;
        start = r[0];
        end = r[1];
      }
      pushHit(cands, start, end, category, ruleId, validation, shape);
    }
  } finally {
    re.lastIndex = 0;
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 身份证（GB 11643-1999 / ISO 7064 MOD 11-2）
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * 加权因子来源：GB 11643-1999 附录 B（ISO 7064 MOD 11-2）。
 * S = Σ(a_i × W_i)（i = 1..17），校验码 = 10X98765432[S mod 11]。
 * 误报风险：校验位只把随机串的误报率压到 1/11，所以还必须叠加
 *   ① 省级行政区划码合法（11–82）② 出生日期真实且不晚于今天 ③ 区划码非 000000。
 */
const ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
const ID_CHECK_TABLE = '10X98765432';

/** 现行 31 个省级行政区划前缀（11–82 区间内的真实取值，其余视为“废止/未知区划”）。 */
const PROVINCE_PREFIX = new Set([
  11, 12, 13, 14, 15,
  21, 22, 23,
  31, 32, 33, 34, 35, 36, 37,
  41, 42, 43, 44, 45, 46,
  50, 51, 52, 53, 54,
  61, 62, 63, 64, 65,
  71, 81, 82,
]);

/** 由前 17 位算第 18 位校验码。 */
function idCheckChar(s17) {
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    sum += (s17.charCodeAt(i) - 48) * ID_WEIGHTS[i];
  }
  return ID_CHECK_TABLE[sum % 11];
}

/**
 * 日期合法性：年 1900..今天，且必须是真实存在的日历日（用 Date 反算验证，能拦 2/30 这类）。
 * 注意 Date.UTC(1900, ...) 不会被当作 1900+1900，只有 0..99 才做 1900 偏移，所以安全。
 */
function dateOk(year, month, day, nowMs) {
  if (year < 1900 || month < 1 || month > 12 || day < 1 || day > 31) return false;
  const t = Date.UTC(year, month - 1, day);
  const d = new Date(t);
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) {
    return false;
  }
  return t <= nowMs;
}

/**
 * 18 位身份证的完整校验；通过返回 ruleId，不通过返回 null。
 *
 * 区划码判定：
 *   - 明显非法（前两位不在 11–82 / 六位全 0）→ 直接丢（不报）；
 *   - 校验位、日期都对，但省级前缀不在现行省份表里（或县码为 00）→ 仍然报，
 *     ruleId 降级为 `idcard.cn18.unknown-division`，便于运营侧排查历史废止码
 *     （lead 明确要求：区划码未知也要报，不要丢）。
 */
function id18RuleId(value, nowMs) {
  const region = value.slice(0, 6);
  const prov = +region.slice(0, 2);
  if (!(prov >= 11 && prov <= 82)) return null;
  if (region === '000000') return null;

  const year = +value.slice(6, 10);
  const month = +value.slice(10, 12);
  const day = +value.slice(12, 14);
  if (!dateOk(year, month, day, nowMs)) return null;

  if (idCheckChar(value.slice(0, 17)) !== value[17].toUpperCase()) return null;

  const knownDivision = PROVINCE_PREFIX.has(prov) && region.slice(4) !== '00';
  return knownDivision ? 'idcard.cn18.checksum' : 'idcard.cn18.unknown-division';
}

/**
 * 15 位旧证号：6 位区划 + YYMMDD + 3 位顺序码，**没有校验位**，因此天然吵。
 * 只在下列之一成立时报（顺序即证据强弱，ruleId 据此区分）：
 *   (a) 前后 40 字符内出现 身份证/证件号/身份/ID 之类上下文；
 *   (b) 同一行紧邻一个“严格模式”人名命中；
 *   (c) 升级成 18 位（第 7 位前插 "19"）后能通过 MOD 11-2。
 *
 * ⚠️ 已知局限（已向 lead 报告）：(c) 对纯 15 位输入是**推导式**校验 ——
 * 18 位校验码本来就是由前 17 位算出来的，所以恒成立。真正起过滤作用的是
 * “省级区划合法 + 出生日期真实 + 顺序码非 000”这三条；若后续要更强精度，
 * 需要接入完整六位行政区划表或要求 (a)/(b)。
 */
const RE_ID_18 = /(?<!\d)(\d{17}[\dXx])(?!\d)/g;
const RE_ID_15 = /(?<!\d)(\d{15})(?!\d)/g;
const ID_CONTEXT_RE = /身份证|证件号|身份证号|身份|(?<![A-Za-z])ID(?![A-Za-z])/i;

function hasIdContext(text, start, end) {
  const from = Math.max(0, start - 40);
  const to = Math.min(text.length, end + 40);
  return ID_CONTEXT_RE.test(text.slice(from, to));
}

function nearNameOnSameLine(text, names, start, end) {
  if (!names || names.length === 0) return false;
  for (const nm of names) {
    if (nm.end <= start) {
      const gap = text.slice(nm.end, start);
      if (gap.length <= 6 && gap.indexOf('\n') === -1 && gap.indexOf('\r') === -1) return true;
    } else if (end <= nm.start) {
      const gap = text.slice(end, nm.start);
      if (gap.length <= 6 && gap.indexOf('\n') === -1 && gap.indexOf('\r') === -1) return true;
    }
  }
  return false;
}

function upgrade15To18(value) {
  const s17 = value.slice(0, 6) + '19' + value.slice(6);
  return s17 + idCheckChar(s17);
}

function scanIdcards(text, cands, nowMs, nameEvidence) {
  // ---- 18 位 ----
  RE_ID_18.lastIndex = 0;
  let m;
  try {
    while ((m = RE_ID_18.exec(text)) !== null) {
      const v = m[0];
      const ruleId = id18RuleId(v, nowMs);
      if (!ruleId) continue;
      pushHit(cands, m.index, m.index + v.length, 'idcard', ruleId, 'mod11_2', 'cn-id-18');
    }
  } finally {
    RE_ID_18.lastIndex = 0;
  }

  // ---- 15 位 ----
  RE_ID_15.lastIndex = 0;
  try {
    while ((m = RE_ID_15.exec(text)) !== null) {
      const v = m[0];
      const region = v.slice(0, 6);
      const prov = +region.slice(0, 2);
      if (!(prov >= 11 && prov <= 82)) continue;
      if (region === '000000') continue;
      // 出生年固定 19xx（15 位证是 1999 年前签发的老号）
      if (!dateOk(1900 + +v.slice(6, 8), +v.slice(8, 10), +v.slice(10, 12), nowMs)) continue;
      if (v.slice(12, 15) === '000') continue; // 顺序码全 0 不是合法人

      const start = m.index;
      const end = start + 15;
      let ruleId = null;
      let validation = null;
      if (hasIdContext(text, start, end)) {
        ruleId = 'idcard.cn15.context';
        validation = 'date';
      } else if (nearNameOnSameLine(text, nameEvidence, start, end)) {
        ruleId = 'idcard.cn15.name';
        validation = 'date';
      } else {
        // (c) 晋升 18 位；见上方“已知局限”注释。
        const up = upgrade15To18(v);
        if (id18RuleId(up, nowMs)) {
          ruleId = 'idcard.cn15.upgraded';
          validation = 'mod11_2';
        }
      }
      if (!ruleId) continue;
      pushHit(cands, start, end, 'idcard', ruleId, validation, 'cn-id-15');
    }
  } finally {
    RE_ID_15.lastIndex = 0;
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 银行卡（Luhn + BIN 前缀）
 * ══════════════════════════════════════════════════════════════════════════ */

/** ISO/IEC 7812-1 Luhn（模 10）校验。 */
function luhnOk(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/**
 * 主流 BIN 前缀（银联 62/60xx、Visa 4、MasterCard 51-55/2 系列按需求只收 5[1-5]、
 * Amex 34/37、JCB 35、Discover 6011/65、以及 9 开头的国内部分卡）。
 * 误报风险：Luhn 会把纯数字串的误报压到 1/10，BIN 再压一档，但订单号/流水号
 * 若恰好 16 位且 Luhn 命中仍可能误报；落选则丢弃（宁可漏，先保证可用）。
 */
const BANK_BIN_RE = /^(?:62|6011|65|9|4|5[1-5]|3[47]|35)/;

/**
 * 13–19 位连续数字，允许中间单个空格/短横。
 * 写法上把分隔符放在数字**前面**（`[ -]?\d`），保证匹配一定以数字结尾，
 * 不会把尾随空格吞进 value。
 */
const RE_BANK = /(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)/g;

function scanBankcards(text, cands) {
  RE_BANK.lastIndex = 0;
  let m;
  try {
    while ((m = RE_BANK.exec(text)) !== null) {
      const raw = m[0];
      const digits = raw.replace(/[ -]/g, '');
      if (digits.length < 13 || digits.length > 19) continue;
      if (!BANK_BIN_RE.test(digits)) continue;
      if (!luhnOk(digits)) continue;
      pushHit(cands, m.index, m.index + raw.length, 'bankcard', 'bankcard.luhn', 'luhn', 'bankcard-' + digits.length);
    }
  } finally {
    RE_BANK.lastIndex = 0;
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 统一社会信用代码（GB 32100-2015，MOD 31-3）
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * 字符集：0-9 → 0-9，A=10,…,Y=30，**不含 I O S V Z**（易与 1/0/5/U/2 混淆而剔除）。
 * W[0..16] = [1,3,9,27,19,26,16,17,20,29,25,13,8,24,10,30,28]
 * C18 = 31 - (Σ Ci·Wi mod 31)；得 31 时取 '0'。
 * 来源：GB 32100-2015 附录 A。误报风险极低（真正的校验算法 + 第 1 位登记管理部门码约束），
 * 是识别“法人主体”最可靠的一条规则。
 */
const USCI_CHARSET = '0123456789ABCDEFGHJKLMNPQRTUWXY';
const USCI_WEIGHTS = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28];
const USCI_VALUE = new Map();
for (let i = 0; i < USCI_CHARSET.length; i++) USCI_VALUE.set(USCI_CHARSET[i], i);

/** 第 1 位登记管理部门码：1 机构编制 / 5 民政（社会组织）/ 9 工商（企业）/ Y 其他。 */
const USCI_LEAD_CHARS = '159Y';

const RE_USCI = /(?<![0-9A-Za-z])[0-9A-HJ-NP-RTU-WY]{18}(?![0-9A-Za-z])/g;

function usciCheckChar(s17) {
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    const v = USCI_VALUE.get(s17[i]);
    if (v === undefined) return null;
    sum += v * USCI_WEIGHTS[i];
  }
  const c = 31 - (sum % 31);
  return c === 31 ? '0' : USCI_CHARSET[c];
}

function usciOk(s) {
  if (USCI_LEAD_CHARS.indexOf(s[0]) === -1) return false;
  return usciCheckChar(s.slice(0, 17)) === s[17];
}

function scanUsci(text, cands) {
  RE_USCI.lastIndex = 0;
  let m;
  try {
    while ((m = RE_USCI.exec(text)) !== null) {
      const v = m[0];
      if (!usciOk(v)) continue;
      pushHit(cands, m.index, m.index + 18, 'org', 'org.cn.usci', 'mod31_3', 'cn-usci');
    }
  } finally {
    RE_USCI.lastIndex = 0;
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 电话 / 邮箱
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * 大陆手机号：只认 `1[3-9]` + 9 位数字 + 前后数字边界，**不写死号段表**。
 * 号段表写死会漏掉新放号段（193/196/199…），漏一个号就是一次泄露；
 * 多换一个只多花一次替换。号段信息只用于展示运营商，不参与判定。
 * 允许 +86/86 前缀，以及号码内部的单个空格/短横（“+86 138 0000 1111”）。
 */
const RE_MOBILE = /(?<!\d)(?:\+?86[ -]?)?1[3-9](?:[ -]?\d){9}(?!\d)/g;
/** 座机：区号 0xx / 0xxx + 7–8 位号码，可选“转/ ext / -”分机。 */
const RE_LANDLINE = /(?<!\d)0\d{2,3}[ -]?\d{7,8}(?:[ -]?(?:转|ext\.?)\s?\d{1,6}|-\d{1,6})?(?!\d)/gi;

function scanPhones(text, cands) {
  pushMatchAll(cands, text, RE_MOBILE, 'phone', 'phone.cn.mobile', 'none', 'cn-mobile');
  pushMatchAll(cands, text, RE_LANDLINE, 'phone', 'phone.cn.landline', 'none', 'cn-landline');
}

/**
 * 邮箱：实用正则（本地部分允许 + 标签，域名允许多级）。
 * 结尾用 `[A-Za-z]{2,}` 收口，天然不会把尾随的 `. , ; >` 吃进 value。
 */
const RE_EMAIL = /(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?\.[A-Za-z]{2,}(?![A-Za-z0-9\-])/g;

function scanEmails(text, cands) {
  pushMatchAll(cands, text, RE_EMAIL, 'email', 'email.address', 'none', 'email');
}

/* ══════════════════════════════════════════════════════════════════════════
 * 地址（中文）
 * ══════════════════════════════════════════════════════════════════════════ */

/** 门牌号 token：数字 + 号/室/楼/栋/单元/层… */
const RE_HOUSE = /(?<!\d)(\d{1,5})(号楼|号院|号|室|楼|栋|座|单元|层|房|户)/g;
/** 道路类 token（“道”单独出现太容易撞“知道”，只收复合词与路/街/巷等）。 */
const ROAD_TOKEN_RE = /(?:大道|街道|胡同|路|街|巷|弄|村|镇|乡)/g;
/** 路名与门牌号之间只允许这些字符（防止跨句拼出假地址）。 */
const ADDRESS_GAP_RE = /^[\u4e00-\u9fa5A-Za-z0-9\-#]{0,20}$/;
/**
 * 向前回溯时的“刹车词”：地址前常见的介词/动词/代词。
 * 误报风险：地址没有校验算法，完全靠“道路 token + 门牌号”共现 + 这些刹车词控制；
 * 仍可能把“我去过建国路88号”里的修饰词带进来（只影响脱敏跨度，不影响是否命中）。
 */
const ADDRESS_STOP_CHARS = new Set(Array.from('在住是的地了到去往从和与及或为于给向我你他她它们这那个有无回进出处址请将把被让对要会能可按根依据坐落位等'));

function scanAddresses(text, cands) {
  RE_HOUSE.lastIndex = 0;
  let m;
  try {
    while ((m = RE_HOUSE.exec(text)) !== null) {
      const numStart = m.index;
      const numEnd = numStart + m[0].length;
      const limit = Math.max(0, numStart - 30);

      // 1) 门牌号前 30 字符内必须出现道路类 token（取最近的一个）
      const win = text.slice(limit, numStart);
      ROAD_TOKEN_RE.lastIndex = 0;
      let road = null;
      let r;
      while ((r = ROAD_TOKEN_RE.exec(win)) !== null) road = { rel: r.index, len: r[0].length };
      ROAD_TOKEN_RE.lastIndex = 0;
      if (!road) continue;

      const roadStart = limit + road.rel;
      const roadEnd = roadStart + road.len;
      // 2) token 与门牌号之间必须是干净片段
      const gap = text.slice(roadEnd, numStart);
      if (!ADDRESS_GAP_RE.test(gap)) continue;
      if (/[在是的地和与及或为于给向对从到去了把被让将]/.test(gap)) continue;

      // 3) 向前扩展出路名/行政区（遇到刹车词、非汉字或超过 30 字就停）
      let s = roadStart;
      let cjk = 0;
      while (s > 0 && cjk < 30) {
        if (!isCjkCode(text.charCodeAt(s - 1))) break;
        if (ADDRESS_STOP_CHARS.has(text[s - 1])) break;
        s--;
        cjk++;
      }
      // 道路 token 前至少要有 1 个汉字，否则是“路88号”这种噪点
      if (roadStart - s < 1) continue;

      // 4) 向后吞掉门牌后缀（3单元 / 501室 / 2号楼…）
      let e = numEnd;
      for (let k = 0; k < 4; k++) {
        const rest = text.slice(e, e + 8);
        const mm = /^(?:\d{1,4})?(?:号楼|号院|单元|号|楼|栋|座|层|室|房|户|院)/.exec(rest);
        if (!mm) break;
        e += mm[0].length;
      }

      const span = e - s;
      if (span < 4 || span > 60) continue;
      pushHit(cands, s, e, 'address', 'address.cn', 'none', 'cn-address');
      RE_HOUSE.lastIndex = e;
    }
  } finally {
    RE_HOUSE.lastIndex = 0;
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 人名（中文，姓氏表 + 上下文锚定）
 * ══════════════════════════════════════════════════════════════════════════ */

/** 常见百家姓（单字，100+）。 */
const SURNAME_CHARS =
  '王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤' +
  '常温康施文牛樊葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍涂成苗谷盛曲翁冉骆蓝路游辛靳管柴蒙鲍华喻祁蒲房滕屈饶解牟艾尤阳时穆农司卓古吉缪简车项连芦麦褚娄窦戚岑景党宫费卜冷晏席卫米柏宗瞿桂全佟应臧闵苟邬边卞姬师和仇栾隋商刁沙荣巫寇桑郎甄丛仲虞敖巩明佘池查麻苑迟邝';

/** 常见复姓。 */
const COMPOUND_SURNAMES = [
  '欧阳', '司马', '诸葛', '上官', '东方', '皇甫', '尉迟', '令狐', '慕容', '长孙',
  '宇文', '司徒', '公孙', '独孤', '南宫', '西门', '夏侯', '轩辕', '端木', '澹台',
];
const COMPOUND_FIRST_CHARS = new Set(COMPOUND_SURNAMES.map((s) => s[0]));

const SURNAME_SET = new Set(Array.from(SURNAME_CHARS));

/**
 * 不能出现在“名”里的字符（连词/助词/动词/职衔）。
 * 作用：贪婪取 1–2 字名后，把这些字符从尾部剔掉，避免“张总”“张三负责”这类误报；
 * 同时作为**名的延伸终止符**——“张伟和另外两位同事”里“和”是连词，不能吃进名字
 * （否则会得到“张伟和”这种词内切割），正确处理是“张伟”。
 * 误报风险：会漏掉以这些字结尾/开头的真名（如“李和平”），这是有意接受的取舍
 * ——严格模式默认只在锚定上下文里启用，宁可漏几个人名，也不要大面积误伤正常文本。
 */
const NAME_NEG_CHARS = new Set(
  Array.from(
    '的了是都在也还把被让给从向到对于以为之所而则因但并且有无不没很太更最要会能可应需请将已未曾正刚才只仅共各每些个位件次上下中内外前后里边间处头尾总说写发收打来去做用买卖签复核审批同意志们我你他她它这那就什么怎吗呢吧啊工董和与或及员等'
  )
);

/** 职衔/称谓词：命中则把人名截断在它之前。 */
const NAME_TITLE_WORDS = [
  '先生', '女士', '小姐', '经理', '主任', '老师', '同学', '医生', '助理', '顾问',
  '律师', '主管', '总监', '会计', '老板', '博士', '教授', '秘书', '专员', '董事',
  '师傅', '同志', '代表', '负责人', '联系人',
];

/**
 * 双字/三字常用词拒绝表（实测误报：项目 / 和平 / 和谐 / 应当 / 任何 …）。
 *
 * 这些词都是“姓氏字 + 常用字”的形态，靠上下文锚定拦不住（“联系人：项目负责人”
 * 里锚点是合法的），必须用词表硬拒。命中后按**最长 2/3 字前缀**判定，
 * 所以“项目组”“和平区”这类扩展词也会一起被拒。
 */
const NAME_STOP_WORDS = new Set([
  // —— lead 从审计日志里捞出来的 ——
  '项目', '方案', '和平', '和谐', '应当', '应付', '任何', '何时', '何种', '张开', '张量',
  '李度', '王权', '赵氏', '欧元', '黄线', '白名单', '黑名单', '常规', '程序', '重点',
  '金额', '钱包', '铁律', '银行', '队伍', '段落', '费用',
  // —— 同形态的高频词补充 ——
  '时间', '时期', '时代', '明显', '明白', '明确', '阳光', '阳台', '陆续', '陆地',
  '成立', '成本', '成为', '成功', '文化', '文明', '文章', '文件', '方式', '方面',
  '方法', '方向', '高度', '高级', '高兴', '黄金', '黄色', '白色', '白天', '马上',
  '马路', '苏州', '苏醒', '沈阳', '严重', '严谨', '简单', '简直', '车辆', '车站',
  '车间', '江山', '江河', '林业', '林区', '石油', '石头', '沙滩', '华丽', '华人',
  '任务', '任职', '任命', '任免', '于是', '温度', '温暖', '汤圆', '汤匙', '费心',
  '费力', '郑重', '周到', '周围', '周报', '金库', '金融', '章程', '常理', '常识',
  '程序化', '管理层', '用户', '里程', '康养', '何时何地', '何况', '何苦', '余额',
  '余光', '余额宝', '管线', '管道', '药物', '药品', '客车', '车间主任', '钱包余额',
]);

/**
 * 人名尾巴不能紧跟的助词/连词/量词（“张伟和”“李四的”这类切开错误）。
 * 注：这些字已经同时放进 NAME_NEG_CHARS 作为延伸终止符，因此正常情况不会粘到名字上；
 * 这里再兜一层，处理“名字已经吃满 2 字、下一个字恰好是助词”的边界。
 */
const NAME_FOLLOW_REJECT = new Set(Array.from('员们等'));

/** 严格模式上下文锚点（必须出现在姓氏前 12 字符内）。 */
const NAME_ANCHORS = ['姓名', '联系人', '负责人', '客户', '法定代表人', '签字', '签收', '身份证名', '户名', '收款人'];

/** 锚点与人名之间允许出现的字符：标点/空白/连接符。 */
const NAME_GAP_PUNCT_RE = /^[\s:：,，、.。;；\-—_/()（）]*$/;
/** 也允许一个系词：“负责人是张三”“客户名为李四”。 */
const NAME_GAP_COPULA_RE = /^\s*(?:是|为|叫|名叫|名为)\s*$/;

/**
 * 锚定判定（严格模式）。
 *
 * 契约只要求“姓氏前 12 字符内出现锚点”，但纯窗口判定会把
 * “客户反馈：功能正常，但响应偏慢”里的“应偏慢”当成人名（“客户”命中了锚点）。
 * 这里收紧为：取姓名前 12 字符内**最靠右**的锚点，锚点与姓氏之间只允许
 * 标点/空白/连接符或一个系词。这样既覆盖真实写法（“联系人：张三”“负责人是张三”“户名张三”），
 * 又不会被远程锚点误伤。
 */
function nameAnchorOk(text, pos) {
  const from = Math.max(0, pos - 12);
  const win = text.slice(from, pos);
  let anchorEnd = -1;
  for (let i = 0; i < NAME_ANCHORS.length; i++) {
    const at = win.lastIndexOf(NAME_ANCHORS[i]);
    if (at === -1) continue;
    const end = from + at + NAME_ANCHORS[i].length;
    if (end > anchorEnd) anchorEnd = end;
  }
  if (anchorEnd < 0) return false;
  const gap = text.slice(anchorEnd, pos);
  if (gap.length === 0) return true;
  return NAME_GAP_PUNCT_RE.test(gap) || NAME_GAP_COPULA_RE.test(gap);
}

function titleAt(text, pos) {
  for (let i = 0; i < NAME_TITLE_WORDS.length; i++) {
    if (text.startsWith(NAME_TITLE_WORDS[i], pos)) return true;
  }
  return false;
}

/**
 * 扫描人名。
 * strict = true（默认）：只有“姓氏前 12 字符内出现锚点”才认定（见 NAME_ANCHORS），
 *   不做裸匹配，避免把“张总”“数字经济”“王先生”之类当人名；
 * strict = false：裸扫描，误报率显著上升，仅为显式开启时使用。
 */
function scanNames(text, cands, strict) {
  const n = text.length;
  for (let i = 0; i < n; i++) {
    if (!isCjkCode(text.charCodeAt(i))) continue;

    // 复姓优先
    let surnameLen = 0;
    if (COMPOUND_FIRST_CHARS.has(text[i])) {
      for (let k = 0; k < COMPOUND_SURNAMES.length; k++) {
        if (text.startsWith(COMPOUND_SURNAMES[k], i)) {
          surnameLen = 2;
          break;
        }
      }
    }
    if (surnameLen === 0) {
      if (!SURNAME_SET.has(text[i])) continue;
      surnameLen = 1;
    }

    // 姓氏后必须还能接上汉字
    if (!isCjkCode(text.charCodeAt(i + surnameLen))) continue;
    if (strict && !nameAnchorOk(text, i)) continue;

    // 名 1–2 字
    let j = i + surnameLen;
    let given = 0;
    while (j < n && given < 2) {
      if (!isCjkCode(text.charCodeAt(j))) break;
      if (NAME_NEG_CHARS.has(text[j])) break;
      if (j > i + surnameLen && titleAt(text, j)) break;
      j++;
      given++;
    }
    if (given === 0) continue;
    // 首字就是职衔（“张经理”“王先生”）→ 不是人名
    if (titleAt(text, i + surnameLen)) continue;

    // 常用词硬拒（项目 / 和平 / 明显 …，含“项目组”“和平区”这类扩展形态）
    const full = text.slice(i, j);
    if (NAME_STOP_WORDS.has(full)) continue;
    if (full.length >= 2 && NAME_STOP_WORDS.has(full.slice(0, 2))) continue;

    // 尾巴紧跟助词/连词 → 说明是词内切割（“张伟和”“李四的”）
    if (j < n && NAME_FOLLOW_REJECT.has(text[j])) continue;

    pushHit(cands, i, j, 'name', strict ? 'name.cn.anchor' : 'name.cn.loose', 'none', 'cn-name');
  }
  return cands;
}

/* ══════════════════════════════════════════════════════════════════════════
 * 公司/客户名
 * ══════════════════════════════════════════════════════════════════════════ */

/** 中文公司后缀（长的放前面，避免“有限公司”抢先匹配掉“股份有限公司”）。 */
const ORG_ZH_SUFFIX_RE =
  /(?:股份有限公司|有限责任公司|有限公司|集团|控股|银行|科技|网络|实业|投资|咨询|事务所|医院|学校|研究院|工作室)/g;

/**
 * 公司名回溯时**硬刹车**字符。
 *
 * 只放“几乎不可能出现在企业名称里”的虚词/助词，以及行政区划、门牌类字
 * （“深圳市腾讯计算机系统有限公司”回溯到“市”即停 → 只脱敏“腾讯计算机系统有限公司”，
 * 地名本身不是敏感主体）。
 *
 * ⚠️ 刻意**不**放 为 / 有 / 和 / 与 / 及 / 或 / 来 / 去 / 用 / 做 / 发 / 中 等字：
 * “华为技术有限公司”“有研科技集团”“用友网络”这些真实企业名都含这些字，
 * 设为硬刹车会把名字截断。这些字改由“前导赘词裁剪”（ORG_LEAD_CHARS）处理。
 *
 * 误报风险：公司名没有校验算法，只能靠后缀 + 边界启发式；可能把
 * “某某科技”这类非主体名词也算进来，名字边界也可能偏长/偏短，
 * 建议按工作区配 dictionary 提升精度。
 */
const ORG_HARD_STOP_CHARS = new Set(
  Array.from(
    '的了是在把被让给从向到对于以等们我你他她它这那个不没很太更最要会能可应需请将已未曾正刚才只仅共各每些件次说写收打买卖签复核审批同意志至自按据例如括省市区县镇乡村路街巷号楼栋座室院由跟'
  )
);

/**
 * 前导赘词（多字优先裁剪）。回溯停在“已/与”这类字之后时，头部还可能挂着
 * “我方已与”这类纯叙述成分，从**名字头部**剔掉即可，不影响名字本体。
 */
const ORG_LEAD_TOKENS = [
  '我方', '贵方', '我们', '你们', '他们', '我司', '贵司', '贵公司', '我公司', '本公司',
  '公司', '已经', '已与', '并与', '以及', '包括', '例如', '其中', '同时', '此外', '另外',
  '根据', '按照', '一家', '某家', '旗下', '下属', '分别', '主要',
];

/**
 * 只允许出现在名字**头部**的单字虚词（裁剪后名字仍需 ≥2 字）。
 *
 * 刻意不含 和 / 有：它们常是真实企业名的首字（和平、有研），裁掉会把名字截断
 * —— 截断比多带一个虚词更糟（残留半截名字反而可能拼出可识别信息）。
 */
const ORG_LEAD_CHARS = new Set(
  Array.from('的了是在与及或等我们你他她它们这那个无不没把被让给从向对于以为之所而则因但并且要会能可应需请将已未正刚才只仅共各每些至自按据例如括')
);

/**
 * 从名字头部剔除叙述性赘词（多字词优先，再退化为单字虚词）。
 * 返回裁剪后的起点。
 *
 * ⚠️ 只允许在“回溯结果超过 20 字上限”时调用（见 scanOrgsZh），
 * 且调用方必须保证裁剪后剩余 ≥6 字——否则会把真名切碎：
 * 实测事故是把 `有研科技集团有限公司` 裁成 `科技集团有限公司`、把 `华为技术有限公司` 裁成 `腾讯计算机系统有限公司`。
 */
function trimOrgLead(text, from, suffixStart) {
  let s = from;
  for (let round = 0; round < 8; round++) {
    let moved = false;
    for (let k = 0; k < ORG_LEAD_TOKENS.length; k++) {
      const tok = ORG_LEAD_TOKENS[k];
      if (text.startsWith(tok, s) && suffixStart - (s + tok.length) >= 2) {
        s += tok.length;
        moved = true;
        break;
      }
    }
    if (moved) continue;
    if (suffixStart - s - 1 >= 2 && ORG_LEAD_CHARS.has(text[s])) {
      s++;
      continue;
    }
    break;
  }
  return s;
}

function scanOrgsZh(text, cands) {
  ORG_ZH_SUFFIX_RE.lastIndex = 0;
  let m;
  try {
    while ((m = ORG_ZH_SUFFIX_RE.exec(text)) !== null) {
      const suffixStart = m.index;
      const suffixEnd = suffixStart + m[0].length;

      // 1) 向后回溯最多 24 个汉字（遇到硬刹车停）。
      //    24 是为了给“超长才裁剪”留出判断空间；最终结果仍限制在 20 字内。
      let s = suffixStart;
      while (s > 0 && suffixStart - s < 24) {
        if (!isCjkCode(text.charCodeAt(s - 1))) break;
        if (ORG_HARD_STOP_CHARS.has(text[s - 1])) break;
        s--;
      }

      // 2) 前导裁剪**只在**回溯结果超出合法长度（20 字）时执行，且裁剪后必须 ≥6 字；
      //    否则保留原匹配（宁可多脱一段，也不能把主体名/人名切碎）。
      let rawLen = suffixStart - s;
      if (rawLen > 20) {
        const trimmed = trimOrgLead(text, s, suffixStart);
        if (suffixStart - trimmed >= 6) s = trimmed;
        else s = suffixStart - 20;
      }

      const nameLen = suffixStart - s;
      if (nameLen < 2 || nameLen > 20) continue;

      pushHit(cands, s, suffixEnd, 'org', 'org.zh.suffix', 'none', 'cn-org');
      ORG_ZH_SUFFIX_RE.lastIndex = suffixEnd;
    }
  } finally {
    ORG_ZH_SUFFIX_RE.lastIndex = 0;
  }
}

/** 英文公司后缀。 */
const RE_ORG_EN = /(?<![A-Za-z0-9])(?:Inc|Ltd|LLC|GmbH|Limited|Corp|Co)\.?(?![A-Za-z0-9])/g;
const EN_WORD_RE = /[A-Za-z&.,'\-]+/g;

/**
 * 英文公司名：从后缀向前收集最多 4 个词，丢掉前面的小写功能词
 * （“We work with Acme Inc” → “Acme Inc”）。
 * 误报风险：会带上 The/Our 之类大写功能词；不含空格连写时不会误报。
 */
function scanOrgsEn(text, cands) {
  RE_ORG_EN.lastIndex = 0;
  let m;
  try {
    while ((m = RE_ORG_EN.exec(text)) !== null) {
      const suffixStart = m.index;
      const suffixEnd = suffixStart + m[0].length;
      const from = Math.max(0, suffixStart - 40);
      const seg = text.slice(from, suffixStart);
      const tail = /[A-Za-z][A-Za-z&.,'\- ]*$/.exec(seg);
      if (!tail) continue;

      const off = seg.length - tail[0].length;
      EN_WORD_RE.lastIndex = 0;
      const words = [];
      let w;
      while ((w = EN_WORD_RE.exec(tail[0])) !== null) words.push({ text: w[0], start: w.index });
      EN_WORD_RE.lastIndex = 0;
      if (words.length === 0) continue;

      // 从第一个“首字母大写”的词开始
      let i0 = 0;
      while (i0 < words.length && !/^[A-Z][A-Za-z&.,'\-]*$/.test(words[i0].text)) i0++;
      if (i0 >= words.length) continue;
      let picked = words.slice(i0);
      if (picked.length > 4) picked = picked.slice(-4);

      const start = from + off + picked[0].start;
      let end = suffixEnd;
      // 去掉名字与后缀之间的尾随空格（理论上不会有，防御一下）
      while (end > start && text[end - 1] === ' ') end--;
      if (end - start < 3 || end - start > 60) continue;

      pushHit(cands, start, end, 'org', 'org.en.suffix', 'none', 'en-org');
      RE_ORG_EN.lastIndex = suffixEnd;
    }
  } finally {
    RE_ORG_EN.lastIndex = 0;
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 密钥（secret）
 * ══════════════════════════════════════════════════════════════════════════ */

/** 格式类密钥规则：命中即算，无需上下文（Token 本身就是高熵随机串，误报率低）。 */
const SECRET_PATTERNS = [
  // AWS Access Key ID（新版还有 ASIA / ABIA / ACCA 前缀）
  [/(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}(?![A-Za-z0-9])/g, 'secret.aws.access_key', 'aws-access-key'],
  // GitHub：ghp_/gho_/ghu_/ghs_/ghr_ + 36 位；细粒度 PAT
  [/(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9_])/g, 'secret.github.token', 'github-token'],
  // GitLab：个人 / 运行器 token
  [/(?<![A-Za-z0-9_])(?:glpat|glrt)-[A-Za-z0-9_-]{20,}/g, 'secret.gitlab.token', 'gitlab-token'],
  // Slack：bot/app/user token 与 Incoming Webhook URL
  [/(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{10,}/g, 'secret.slack.token', 'slack-token'],
  [/https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g, 'secret.slack.webhook', 'slack-webhook-url'],
  // Slack 应用级 token（xapp-…）
  [/(?<![A-Za-z0-9_])xapp-\d-[A-Za-z0-9]+-\d+-[a-z0-9]+/g, 'secret.slack.app_token', 'slack-app-token'],
  // Google API key（AIza + 35 位）
  [/(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])/g, 'secret.google.api_key', 'google-api-key'],
  // 阿里云 AccessKeyId / 腾讯云 SecretId
  [/(?<![A-Za-z0-9])LTAI[A-Za-z0-9]{12,}/g, 'secret.alibaba.access_key', 'aliyun-access-key'],
  [/(?<![A-Za-z0-9])AKID[A-Za-z0-9]{13,}/g, 'secret.tencent.secret_id', 'tencent-secret-id'],
  // Stripe live key
  [/(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{16,}/g, 'secret.stripe.key', 'stripe-key'],
  // Shopify access token（shpat_ + 32 hex）
  [/(?<![A-Za-z0-9])shpat_[a-fA-F0-9]{32}(?![a-fA-F0-9])/g, 'secret.shopify.token', 'shopify-token'],
  // HuggingFace（实际 token 为大小写混合，这里用超集避免漏报）
  [/(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{34,}(?![A-Za-z0-9])/g, 'secret.huggingface.token', 'huggingface-token'],
  // Azure AD 客户端密钥（形如 xxx8Q~yyyy…）
  [/(?<![A-Za-z0-9_~.])[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.\-]{31,34}(?![A-Za-z0-9_~.\-])/g, 'secret.azure.client_secret', 'azure-client-secret'],
  // JWT（三段 base64url，前两段以 eyJ = '{"' 开头）
  [/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g, 'secret.jwt', 'jwt'],
];

/** PEM 私钥块（跨行，含 PKCS#1/8、EC、OpenSSH、PGP）。 */
const PEM_BLOCK = '(?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK)';
const RE_PEM = new RegExp('-{5}BEGIN ' + PEM_BLOCK + '-{5}[\\s\\S]*?(?:-{5}END ' + PEM_BLOCK + '-{5}|$)', 'g');

/** 连接串口令：scheme://user:password@host */
const RE_CONN_PASSWORD =
  /(?<![A-Za-z0-9+.\-])(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/[^\s:@\/]{1,64}:([^\s@\/]{1,128})@/gid;

/** Authorization: Bearer / Basic */
const RE_HEADER_BEARER = /Authorization\s*:\s*Bearer\s+([A-Za-z0-9\-._~+\/]+=*)/gid;
const RE_HEADER_BASIC = /Authorization\s*:\s*Basic\s+([A-Za-z0-9+\/]+=*)/gid;

/**
 * .env 风格键值：只脱敏值，键名保持原文（人要看懂“哪个配置泄露了”）。
 * 误报风险：英文散文里出现 “token: 8 位以上” 的表述会被误伤，
 * 但漏报成本远高于误伤成本，这里选择宁多脱。
 */
const RE_ENV_VALUE =
  /(?:^|[^A-Za-z0-9_])(?:[A-Z][A-Z0-9_]*_)?(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET)\s*[=:]\s*["']?([A-Za-z0-9_\-/+.]{8,})/gid;

/** AWS Secret Access Key：40 位 base64ish，必须紧跟关键词（单靠形状误报太多）。 */
const RE_AWS_SECRET =
  /(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gid;

/** OpenAI / Anthropic / DeepSeek 等 `sk-` 家族。 */
const RE_SK_KEY = /(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}/g;

function scanSecrets(text, cands) {
  // 1) 格式类（顺序即同分同长时的裁决顺序：越具体越靠前）
  for (let i = 0; i < SECRET_PATTERNS.length; i++) {
    const p = SECRET_PATTERNS[i];
    pushMatchAll(cands, text, p[0], 'secret', p[1], 'none', p[2]);
  }

  // 2) `sk-` 家族：按前缀给不同 ruleId，方便审计区分供应商
  RE_SK_KEY.lastIndex = 0;
  let m;
  try {
    while ((m = RE_SK_KEY.exec(text)) !== null) {
      const v = m[0];
      let ruleId = 'secret.openai.key';
      let shape = 'sk-key';
      if (v.startsWith('sk-ant-')) {
        ruleId = 'secret.anthropic.key';
        shape = 'sk-ant-key';
      } else if (v.startsWith('sk-proj-')) {
        ruleId = 'secret.openai.project_key';
        shape = 'sk-proj-key';
      }
      pushHit(cands, m.index, m.index + v.length, 'secret', ruleId, 'none', shape);
      RE_SK_KEY.lastIndex = m.index + v.length;
    }
  } finally {
    RE_SK_KEY.lastIndex = 0;
  }

  // 3) PEM 私钥整块
  pushMatchAll(cands, text, RE_PEM, 'secret', 'secret.pem.private_key', 'none', 'pem-private-key');

  // 4) 连接串口令（只脱敏口令，不动 user/host）
  pushCaptureAll(cands, text, RE_CONN_PASSWORD, 'secret', 'secret.connection_string.password', 'none', 'conn-string-password');

  // 5) Authorization 头（只脱敏凭证）
  pushCaptureAll(cands, text, RE_HEADER_BEARER, 'secret', 'secret.header.bearer', 'none', 'http-bearer');
  pushCaptureAll(cands, text, RE_HEADER_BASIC, 'secret', 'secret.header.basic', 'none', 'http-basic');

  // 6) AWS Secret Access Key（关键词邻近）。
  //    必须排在 .env 通用键值规则**之前**：`SECRET=<40 位 base64>` 两条规则会命中同一区间，
  //    同分同长时先入者胜，这里要让更具体的 aws.secret_key 拿到 ruleId。
  pushCaptureAll(cands, text, RE_AWS_SECRET, 'secret', 'secret.aws.secret_key', 'none', 'b64-40');

  // 7) .env 风格（只脱敏值；尾随句点剔除，避免把中文标点前的“.”吃掉）
  //    值准入：必须含数字或 +/=_ 之一；首字母大写的驼峰标识符（ToolPermissionToken）不报。
  pushCaptureAll(cands, text, RE_ENV_VALUE, 'secret', 'secret.env.value', 'none', 'env-value', (s, e) => {
    while (e > s && text.charCodeAt(e - 1) === 46 /* . */) e--;
    if (e <= s) return null;
    const v = text.slice(s, e);
    if (!/[0-9+/=_]/.test(v)) return null; // 纯字母（哪怕驼峰）当标识符处理
    if (CAMEL_WORD_RE.test(v)) return null; // CamelCase 标识符
    return [s, e];
  });

  // 8) generic 兜底：关键词紧邻赋值符 + 高熵值
  scanGenericSecrets(text, cands);
}

/**
 * generic secret 兜底（gitleaks 式“关键词邻近 + 熵”，但**不引入全局 stopword**）。
 *
 * 实测误报（真实审计日志）逼出来的收紧，逐条对应：
 *   ① 候选值不能是路径/URL 片段：以 `/` `\` 开头、或含 `://` 一律排除；
 *   ② 不能是纯小写 slug（`^[a-z0-9]+(?:[-._/][a-z0-9]+)+$`）——挡住
 *      `deepseek-v4.1-flash` 这类模型名/slug；
 *   ③ 关键词必须**紧邻**赋值符：key|token|secret|password|credential 之后 0–8 字符内出现
 *      `=` / `:`（同时覆盖 `:=` / `=>`），而不是“20 字符窗口内出现过关键词”；
 *   ④ 值长度 ≥ 20，且字符集至少混两类（大写 / 小写 / 数字 / `+/=`）；
 *   ⑤ 排除已有厂商前缀的（那些有专门规则）、UUID、纯 hex 摘要（sha256 之类）、EXAMPLE 示例值；
 *   ⑥ 片段完整性：值前后不能还紧接同类字符——长 base64 里截出来的一段不算密钥。
 *
 * 为什么不抄 gitleaks 的全局 stopword：`abcdefghijklmnopqrstuvwxyz` 这类词表会把中文
 * 场景中的密钥整段吞掉（中文里经常紧贴字母），导致漏报。
 *
 * 残余误报风险：形状上真正像随机 token 的文本（如独立的 base64 片段）仍可能被多脱一次。
 * 遇到这类业务噪声，应优先用 allowPatterns 按工作区抑制，而不是继续放宽本规则。
 */
const GENERIC_VALUE_CHARS = /[A-Za-z0-9_\-+/=.~]/;

/** 关键词：只保留能真正指向“密钥赋值”的 5 个词（access/auth/api 太宽，会命中路径/说明文本）。 */
const GENERIC_KEYWORD_RE = /(?:key|token|secret|password|credential)/gi;
/** 关键词后 0–8 个“键名尾段”字符，然后**必须**紧跟赋值符（= / : / := / =>）。 */
const GENERIC_SEP_RE = /^[A-Za-z0-9_\-\s"'[\]]{0,8}?(?::=|=>|[=:])\s*["']?/;
/** 值：≥20 字符（上限 128 视为“长串片段”，直接排除）。 */
const GENERIC_VALUE_RE = /^[A-Za-z0-9_\-+/=.~]{20,128}/;
const PURE_IDENTIFIER_RE = /^[a-zA-Z_.-]+$/;
const UUID_SHAPE_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const EXAMPLE_TAIL_RE = /EXAMPLE$/;
/** 纯小写 slug：模型名 / 包名 / 路径段（deepseek-v4.1-flash、lodash.merge、a/b/c）。 */
const SLUG_SHAPE_RE = /^[a-z0-9]+(?:[-._/][a-z0-9]+)+$/;
/** 纯 hex：sha256 摘要、object id 之类，不是密钥。 */
const HEX_ONLY_RE = /^[0-9a-fA-F]+$/;
/** 首字母大写的驼峰标识符（ToolPermissionToken / AccessKeyId）：标识符，不是密钥。 */
const CAMEL_WORD_RE = /^[A-Z][a-z]+(?:[A-Z][a-z]+)+$/;
/** 路径 / URL 片段。 */
const URL_OR_PATH_RE = /^[\/\\]|:\/\//;
/** 已有厂商前缀的交给专门规则，generic 不重复报。 */
const VENDOR_PREFIX_RE =
  /^(?:sk-|rk_|pk_|AKIA|ASIA|ABIA|ACCA|gh[pousr]_|github_pat_|glpat-|glrt-|xox[abprs]-|AIza|LTAI|AKID|shpat_|hf_|eyJ|xapp-)/;
const GENERIC_MIN_ENTROPY = 3.5;
/** 值的字符集（用于“片段完整性”判断：前后不能还紧接同类字符）。 */
function isSecretValueChar(code) {
  return (
    (code >= 48 && code <= 57) || // 0-9
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    code === 95 || // _
    code === 45 || // -
    code === 43 || // +
    code === 47 || // /
    code === 61 || // =
    code === 46 || // .
    code === 126 // ~
  );
}

/** 字符集种类数：大写 / 小写 / 数字 / `+/=`。 */
function charClassCount(v) {
  let n = 0;
  if (/[A-Z]/.test(v)) n++;
  if (/[a-z]/.test(v)) n++;
  if (/[0-9]/.test(v)) n++;
  if (/[+\/=]/.test(v)) n++;
  return n;
}

/** generic 候选值的准入判定（见 scanGenericSecrets 上方注释①–⑥）。 */
function genericValueOk(text, value, start, end) {
  if (value.length < 20) return false; // ④ 长度
  if (value.length >= 128) return false; // ⑥ 命中上限 → 是被截断的长串片段

  // ⑥ 片段完整性：前一个字符若仍是值字符（赋值符 = 除外），说明是从长串中间截出来的
  if (start > 0) {
    const prev = text.charCodeAt(start - 1);
    if (prev !== 61 /* = */ && isSecretValueChar(prev)) return false;
  }
  if (end < text.length && isSecretValueChar(text.charCodeAt(end))) return false;

  if (URL_OR_PATH_RE.test(value)) return false; // ① 路径 / URL
  if (SLUG_SHAPE_RE.test(value)) return false; // ② 小写 slug / 模型名
  if (VENDOR_PREFIX_RE.test(value)) return false; // ⑤ 厂商前缀（有专门规则）
  if (UUID_SHAPE_RE.test(value)) return false;
  if (HEX_ONLY_RE.test(value)) return false; // 纯 hex 摘要
  if (CAMEL_WORD_RE.test(value)) return false; // 驼峰标识符
  if (EXAMPLE_TAIL_RE.test(value)) return false; // 官方示例值
  if (PURE_IDENTIFIER_RE.test(value)) return false; // 纯标识符
  if (charClassCount(value) < 2) return false; // ④ 至少混两类
  if (shannonEntropy(value) < GENERIC_MIN_ENTROPY) return false;
  return true;
}

function scanGenericSecrets(text, cands) {
  GENERIC_KEYWORD_RE.lastIndex = 0;
  let m;
  try {
    while ((m = GENERIC_KEYWORD_RE.exec(text)) !== null) {
      const kwEnd = m.index + m[0].length;
      const seg = text.slice(kwEnd, Math.min(text.length, kwEnd + 24));
      const sep = GENERIC_SEP_RE.exec(seg);
      if (!sep) continue;

      const vStart = kwEnd + sep[0].length;
      const vm = GENERIC_VALUE_RE.exec(text.slice(vStart, vStart + 128));
      if (!vm) continue;
      const value = vm[0];
      const vEnd = vStart + value.length;

      // 无论命中与否都跳过整段值，避免在一个长串内部反复重试
      GENERIC_KEYWORD_RE.lastIndex = vEnd;
      if (!genericValueOk(text, value, vStart, vEnd)) continue;

      pushHit(cands, vStart, vEnd, 'secret', 'secret.generic.high_entropy', 'none', 'entropy-generic');
    }
  } finally {
    GENERIC_KEYWORD_RE.lastIndex = 0;
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 自定义词典（custom）
 * ══════════════════════════════════════════════════════════════════════════ */

const ASCII_ONLY_RE = /^[\x20-\x7E]+$/;

/**
 * 词典项按字面量匹配：命中归入 custom（不归 org，避免和公司名规则抢语义）。
 *   - 长度 < minCustomLength 的忽略；
 *   - 纯 ASCII 词做词边界（ACME 不会匹配到 ACMEs 里）；
 *   - 中文直接 indexOf（汉字之间没有空格，加边界反而会漏）；
 *   - 大小写：ASCII 不敏感（用 lowerText 搜索），中文等价。
 * 重叠的多个词条交给统一归并——“同级取更长者”，正好实现“取最长词条”。
 */
function scanCustom(text, haystack, cands, dictionary) {
  for (let k = 0; k < dictionary.length; k++) {
    const entry = dictionary[k];
    const needle = entry.needle;
    let pos = 0;
    while (pos <= haystack.length) {
      const at = haystack.indexOf(needle, pos);
      if (at === -1) break;
      const end = at + needle.length;
      let ok = true;
      if (entry.ascii) {
        if (at > 0 && isAsciiWordCode(text.charCodeAt(at - 1))) ok = false;
        if (ok && end < text.length && isAsciiWordCode(text.charCodeAt(end))) ok = false;
      }
      if (ok) pushHit(cands, at, end, 'custom', 'custom.dictionary', 'none', 'dictionary');
      pos = at + 1;
    }
  }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 占位符 / allowlist / 区间归并
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * 既有占位符区间。
 *
 * 当前网关**默认单方括号** `[EMAIL_1]`，但历史数据/兼容场景里也会出现双方括号
 * `[[EMAIL_1]]`、`[ EMAIL_1 ]`、`[API_KEY_2]`，以及全角括号。这里用宽容形式一次性覆盖：
 *   /\[{1,2}\s*[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*[_-]\d{1,6}\s*\]{1,2}/
 * 只要“字母开头 + 至少一段数字”的括号体都算占位符，就不会把 [TEXT](url) 这类
 * markdown 文本误当占位符（正文里没有数字）。
 *
 * 这些区间必须整段跳过，否则“响应回填 → 再次出网”时会把占位符二次脱敏，
 * 回填表就对不上了。
 */
const PLACEHOLDER_BODY = '[A-Za-z][A-Za-z0-9]*(?:[_-][A-Za-z0-9]+)*[_-]\\d{1,6}';
const RE_PLACEHOLDER = new RegExp(
  '\\[{1,2}\\s*' + PLACEHOLDER_BODY + '\\s*\\]{1,2}' +
    '|［{1,2}\\s*' + PLACEHOLDER_BODY + '\\s*］{1,2}',
  'g'
);

function findPlaceholderRanges(text) {
  const out = [];
  RE_PLACEHOLDER.lastIndex = 0;
  let m;
  try {
    while ((m = RE_PLACEHOLDER.exec(text)) !== null) {
      out.push({ start: m.index, end: m.index + m[0].length });
      RE_PLACEHOLDER.lastIndex = m.index + m[0].length;
    }
  } finally {
    RE_PLACEHOLDER.lastIndex = 0;
  }
  return out;
}

/** 文本小写化；若长度变化（极少数 Unicode 折叠会变长）则放弃，用原文兜底。 */
function lowerSameLength(text) {
  const lower = text.toLowerCase();
  return lower.length === text.length ? lower : null;
}

/** 汇总 allowlist 字面量 + allowPatterns 正则的出现区间。 */
function buildAllowRanges(text, lowerText, literals, patterns) {
  const ranges = [];
  for (let i = 0; i < literals.length; i++) {
    const lit = literals[i];
    if (!lit) continue;
    const hay = lowerText || text;
    const needle = lowerText ? lit.toLowerCase() : lit;
    if (needle.length === 0) continue;
    let pos = 0;
    while (pos <= hay.length) {
      const at = hay.indexOf(needle, pos);
      if (at === -1) break;
      ranges.push({ start: at, end: at + needle.length });
      pos = at + 1;
    }
  }
  for (let i = 0; i < patterns.length; i++) {
    const re = patterns[i];
    re.lastIndex = 0;
    let m;
    try {
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) {
          re.lastIndex = m.index + 1;
          continue;
        }
        ranges.push({ start: m.index, end: m.index + m[0].length });
      }
    } finally {
      re.lastIndex = 0;
    }
  }
  return ranges;
}

/**
 * 覆盖判断预处理：按 start 排序，并算 maxEnd 前缀最大值，
 * 之后用二分查找即可回答“是否存在一个区间完全覆盖 [start,end)”。
 * （区间数可能上千条——例如按行匹配的 allowPattern，所以不能对每条检测做线性扫描。）
 */
function prepareCoverage(ranges) {
  const sorted = ranges.slice().sort((a, b) => a.start - b.start || b.end - a.end);
  const maxEnd = new Array(sorted.length);
  let mx = -1;
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i].end > mx) mx = sorted[i].end;
    maxEnd[i] = mx;
  }
  return { ranges: sorted, maxEnd };
}

function coveredBy(cov, start, end) {
  const ranges = cov.ranges;
  if (ranges.length === 0) return false;
  let lo = 0;
  let hi = ranges.length - 1;
  let idx = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (ranges[mid].start <= start) {
      idx = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return idx >= 0 && cov.maxEnd[idx] >= end;
}

/** 与任一区间相交（占位符用“相交即丢”，比“整体覆盖”更保守也更安全）。 */
function overlapsAny(ranges, start, end) {
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    if (r.start < end && start < r.end) return true;
  }
  return false;
}

/* ══════════════════════════════════════════════════════════════════════════
 * 工厂
 * ══════════════════════════════════════════════════════════════════════════ */

function normalizeStringList(v) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (let i = 0; i < v.length; i++) {
    const s = v[i];
    if (typeof s !== 'string' || s.length === 0) continue;
    out.push(s);
  }
  return out;
}

/**
 * 创建检测器。
 *
 * @param {object} [options]
 * @param {Record<string, boolean>} [options.categories] 类别开关，`false` 表示完全不检测
 * @param {string[]} [options.dictionary] 自定义词典（客户名 / 项目代号）
 * @param {string[]} [options.allowlist] 永不脱敏的字面量（ASCII 大小写不敏感）
 * @param {string[]} [options.allowPatterns] 永不脱敏的正则源串
 * @param {number} [options.minCustomLength=2] 词典项最小长度
 * @param {boolean} [options.nameStrict=true] 人名是否要求上下文锚定
 * @returns {{ detect(text: string): Array<{start:number,end:number,value:string,category:string,ruleId:string,validation:string,shape:string}> }}
 */
export function createDetector(options = {}) {
  const opts = options && typeof options === 'object' ? options : {};

  // ---- 类别开关：缺省视为全开，只有显式 false 才关闭 ----
  const catOpt = opts.categories && typeof opts.categories === 'object' ? opts.categories : {};
  const enabled = {};
  for (let i = 0; i < CATEGORIES.length; i++) {
    const c = CATEGORIES[i];
    enabled[c] = catOpt[c] !== false;
  }

  // ---- 词典（去重 + 预小写） ----
  const minCustomLength = Number.isFinite(opts.minCustomLength) && opts.minCustomLength >= 0 ? opts.minCustomLength : 2;
  const dictionary = [];
  {
    const seen = new Set();
    const raw = normalizeStringList(opts.dictionary);
    for (let i = 0; i < raw.length; i++) {
      const s = raw[i];
      if (s.length < minCustomLength) continue;
      if (seen.has(s)) continue;
      seen.add(s);
      dictionary.push({ raw: s, needle: s.toLowerCase(), ascii: ASCII_ONLY_RE.test(s) });
    }
  }

  // ---- allowlist / allowPatterns ----
  const allowLiterals = normalizeStringList(opts.allowlist);
  const allowPatterns = [];
  {
    const raw = normalizeStringList(opts.allowPatterns);
    for (let i = 0; i < raw.length; i++) {
      try {
        // 非法正则不应该让检测器创建失败（配置写错不能变成“整个网关起不来”）
        allowPatterns.push(new RegExp(raw[i], 'g'));
      } catch {
        /* 忽略非法 pattern */
      }
    }
  }

  const nameStrict = opts.nameStrict !== false;

  const needLower = dictionary.length > 0 || allowLiterals.length > 0;

  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];

    const nowMs = Date.now();
    const cands = [];
    const lowerText = needLower ? lowerSameLength(text) : null;

    // 人名先扫：15 位身份证的 (b) 条件需要“同一行紧邻人名”作为证据。
    let nameCands = null;
    if (enabled.name) nameCands = scanNames(text, [], nameStrict);

    let nameEvidence = nameCands;
    if (enabled.idcard && (!nameCands || !nameStrict)) {
      // name 关闭或宽松模式时，单独跑一遍严格扫描只当证据用（不参与输出）
      nameEvidence = scanNames(text, [], true);
    }

    if (enabled.secret) scanSecrets(text, cands);
    if (enabled.custom && dictionary.length > 0) scanCustom(text, lowerText || text, cands, dictionary);
    if (enabled.idcard) scanIdcards(text, cands, nowMs, nameEvidence);
    if (enabled.bankcard) scanBankcards(text, cands);
    if (enabled.phone) scanPhones(text, cands);
    if (enabled.email) scanEmails(text, cands);
    if (enabled.org) {
      scanUsci(text, cands);
      scanOrgsZh(text, cands);
      scanOrgsEn(text, cands);
    }
    if (enabled.address) scanAddresses(text, cands);
    if (nameCands) {
      for (let i = 0; i < nameCands.length; i++) cands.push(nameCands[i]);
    }

    if (cands.length === 0) return [];

    // ---- 过滤：allowlist 覆盖 / 既有占位符 ----
    const allowRanges = prepareCoverage(buildAllowRanges(text, lowerText, allowLiterals, allowPatterns));
    const placeholderRanges = findPlaceholderRanges(text);

    const filtered = [];
    for (let i = 0; i < cands.length; i++) {
      const c = cands[i];
      if (coveredBy(allowRanges, c.start, c.end)) continue;
      if (placeholderRanges.length > 0 && overlapsAny(placeholderRanges, c.start, c.end)) continue;
      filtered.push(c);
    }
    if (filtered.length === 0) return [];

    // ---- 归并：优先级优先，同级更长的优先 ----
    filtered.sort(
      (a, b) =>
        PRIORITY[a.category] - PRIORITY[b.category] ||
        b.end - b.start - (a.end - a.start) ||
        a.start - b.start
    );

    const taken = new Uint8Array(text.length);
    const kept = [];
    for (let i = 0; i < filtered.length; i++) {
      const c = filtered[i];
      let clash = false;
      for (let p = c.start; p < c.end; p++) {
        if (taken[p]) {
          clash = true;
          break;
        }
      }
      if (clash) continue;
      for (let p = c.start; p < c.end; p++) taken[p] = 1;
      kept.push(c);
    }

    kept.sort((a, b) => a.start - b.start);

    const out = new Array(kept.length);
    for (let i = 0; i < kept.length; i++) {
      const c = kept[i];
      out[i] = {
        start: c.start,
        end: c.end,
        value: text.slice(c.start, c.end),
        category: c.category,
        ruleId: c.ruleId,
        validation: c.validation,
        shape: c.shape,
      };
    }
    return out;
  }

  return { detect, CATEGORIES: CATEGORIES.slice() };
}
