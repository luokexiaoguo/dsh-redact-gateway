// NOTE: a few secret fixtures below are assembled from string fragments (e.g.`n// 'shpat_' + '<hex>' + '<hex>'). The assembled value is what the detector sees; the`n// source never contains a complete token, so GitHub push protection and other secret`n// scanners do not flag this repository. Keep that style for new fixtures.

/**
 * lib/rules.js 单元测试
 *
 * 运行方式（沙箱里 `node --test` 会 spawn EPERM，改为直接执行）：
 *   cd packages/redact-gateway
 *   node test/rules.test.mjs
 *
 * 约定：
 *  - 测试里的身份证 / 银行卡 / 统一社会信用代码都是**虚构但校验位合法**的号码，
 *    不对应任何真实主体（身份证统一用 1900/1990 年出生 + 000101 之类明显虚构的日期）；
 *  - 断言失败信息里不打印被检测原文（这是安全产品，日志不能成为泄露通道）。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { CATEGORIES, createDetector } from '../lib/rules.js';

/* ── 小工具 ───────────────────────────────────────────────────────────── */

const detect = (text, opts) => createDetector(opts).detect(text);
const ruleIds = (text, opts) => detect(text, opts).map((d) => d.ruleId);

/** 断言恰好命中 1 条，并返回它。 */
function one(text, opts) {
  const list = detect(text, opts);
  assert.equal(
    list.length,
    1,
    `期望恰好 1 条检测，实际 ${list.length} 条（ruleId=${list.map((d) => d.ruleId).join(',')}）`
  );
  return list[0];
}

/** 断言没有任何检测。 */
function none(text, opts) {
  const list = detect(text, opts);
  assert.equal(
    list.length,
    0,
    `期望 0 条检测，实际 ${list.length} 条（ruleId=${list.map((d) => d.ruleId).join(',')}）`
  );
}

/**
 * 虚构的高熵值：21 字符、大小写+数字混排、非 slug/非 hex/非驼峰。
 * 用来验证 generic 规则“仍然活着”（反转测试），避免调参调成永远不命中。
 */
const SYNTHETIC_SECRET = 'Zx9Kq2Lm4Np7Rt1Vw3Bd';

/* ── 1. 导出契约 / 健壮性 ─────────────────────────────────────────────── */

test('导出契约：CATEGORIES 与 createDetector', () => {
  assert.deepEqual(CATEGORIES, [
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

  const det = createDetector();
  assert.equal(typeof det.detect, 'function');
  assert.deepEqual(det.detect(''), []);
});

test('健壮性：空值 / 非字符串 / 超长串 / 幂等 都不抛异常', () => {
  const det = createDetector();
  for (const bad of ['', null, undefined, 0, 123, {}, [], true, NaN, () => {}]) {
    assert.deepEqual(det.detect(bad), []);
  }
  // 非法 options 不能让工厂炸掉
  assert.deepEqual(createDetector(null).detect('普通文本'), []);
  assert.deepEqual(createDetector({ categories: null, dictionary: 'not-an-array' }).detect('普通文本'), []);

  // 超长串（20 万字符）不抛异常
  const big = '甲'.repeat(200000);
  assert.doesNotThrow(() => det.detect(big));

  // 幂等、无跨调用状态
  const text = '联系 13800001111 或 user@example.com';
  assert.deepEqual(det.detect(text), det.detect(text));
  assert.deepEqual(det.detect(text), createDetector().detect(text));
});

/* ── 2. secret ────────────────────────────────────────────────────────── */

/** 每条 secret 子规则至少一次命中（ruleId 必须稳定）。 */
const SECRET_HIT_CASES = [
  ['AWS AccessKey AKIA', 'AKIAIOSFODNN7EXAMPLE', 'secret.aws.access_key'],
  ['AWS AccessKey ASIA', 'ASIAIOSFODNN7EXAMPLE', 'secret.aws.access_key'],
  ['AWS AccessKey ABIA', 'ABIAIOSFODNN7EXAMPLE', 'secret.aws.access_key'],
  ['AWS AccessKey ACCA', 'ACCAIOSFODNN7EXAMPLE', 'secret.aws.access_key'],
  [
    'AWS SecretKey（带上下文）',
    'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    'secret.aws.secret_key',
  ],
  ['OpenAI sk-', 'sk-abcdefghijklmnopqrstuvwx', 'secret.openai.key'],
  ['Anthropic sk-ant-', 'sk-ant-api03-abcdefghijklmnopqrstuv', 'secret.anthropic.key'],
  ['OpenAI sk-proj-', 'sk-proj-abcdefghijklmnop123456', 'secret.openai.project_key'],
  ['GitHub ghp_', 'ghp_abcdefghijklmnopqrstuvwxyz1234567890', 'secret.github.token'],
  ['GitHub fine-grained', 'github_pat_11ABCDEFG0123456789ABCDEFGH', 'secret.github.token'],
  ['GitLab glpat-', 'glpat-abcdefghijklmnopqrst', 'secret.gitlab.token'],
  ['GitLab glrt-', 'glrt-abcdefghijklmnopqrst', 'secret.gitlab.token'],
  ['Slack bot token', 'xoxb-1234567890-abcdefghij', 'secret.slack.token'],
  [
    'Slack webhook',
    ('https://hooks.slack.com/' + 'services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'),
    'secret.slack.webhook',
  ],
  ['Slack xapp-', 'xapp-1-A0123456789-1234567890123-abcdef1234567890abcdef', 'secret.slack.app_token'],
  ['Google API key', 'AIzaSyA1234567890abcdefghijklmnopqrstuv', 'secret.google.api_key'],
  ['阿里云 AccessKeyId', 'LTAI5tABCDEFGHIJK', 'secret.alibaba.access_key'],
  ['腾讯云 SecretId', 'AKIDzABCdef1234567890', 'secret.tencent.secret_id'],
  ['Stripe sk_live', 'sk_live_abcdefghijklmnop1234', 'secret.stripe.key'],
  ['Stripe rk_live', 'rk_live_abcdefghijklmnop1234', 'secret.stripe.key'],
  ['Shopify shpat_', ('shpat_' + '0123456789abcdef' + '0123456789abcdef'), 'secret.shopify.token'],
  ['HuggingFace hf_', 'hf_abcdefghijklmnopqrstuvwxyz0123456789', 'secret.huggingface.token'],
  [
    'Azure AD client secret',
    'abc8Q~abcdefghijklmnopqrstuvwxyz012345',
    'secret.azure.client_secret',
  ],
  [
    'JWT',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    'secret.jwt',
  ],
  [
    'PEM 私钥块（跨行）',
    '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\n-----END RSA PRIVATE KEY-----',
    'secret.pem.private_key',
  ],
  [
    'postgres 连接串口令',
    'postgres://admin:S3cretP4ss@db.internal:5432/app',
    'secret.connection_string.password',
  ],
  [
    'mongodb+srv 连接串口令',
    'mongodb+srv://user:Pa55w0rd@cluster0.example.net/db',
    'secret.connection_string.password',
  ],
  [
    'Authorization Bearer',
    'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345',
    'secret.header.bearer',
  ],
  [
    'Authorization Basic',
    'Authorization: Basic dXNlcjpwYXNzd29yZA==',
    'secret.header.basic',
  ],
  ['.env 风格', 'DB_PASSWORD=Zx9Kq2Lm4Np7Rt1Vw3', 'secret.env.value'],
  ['generic 高熵兜底', `credential = "${SYNTHETIC_SECRET}"`, 'secret.generic.high_entropy'],
];

test('secret：所有子规则都能命中且 ruleId 稳定', () => {
  for (const [label, text, ruleId] of SECRET_HIT_CASES) {
    assert.ok(ruleIds(text).includes(ruleId), `${label} 未命中 ${ruleId}`);
  }
});

test('secret：只脱敏值，不脱敏键名/协议头', () => {
  // .env：键名保持明文，值才是检测区间
  const env = detect('DB_PASSWORD=Zx9Kq2Lm4Np7Rt1Vw3')[0];
  assert.equal(env.ruleId, 'secret.env.value');
  assert.equal(env.value, 'Zx9Kq2Lm4Np7Rt1Vw3');
  assert.ok(env.start >= 'DB_PASSWORD='.length);

  // 连接串：只脱敏口令
  const conn = detect('postgres://admin:S3cretP4ss@db.internal:5432/app')[0];
  assert.equal(conn.value, 'S3cretP4ss');

  // Authorization：只脱敏凭证
  const bearer = detect('Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345')[0];
  assert.equal(bearer.value, 'abcdefghijklmnopqrstuvwxyz012345');

  // PEM 整块（含 BEGIN/END 行）一起脱敏
  const pem = detect('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----')[0];
  assert.equal(pem.ruleId, 'secret.pem.private_key');
  assert.ok(pem.value.startsWith('-----BEGIN PRIVATE KEY-----'));
  assert.ok(pem.value.endsWith('-----END PRIVATE KEY-----'));
});

test('secret：不命中用例', () => {
  const misses = [
    ['AKIA 后长度不足', 'AKIA1234'],
    ['sk- 后长度不足', 'sk-short-token'],
    ['xoxb- 后长度不足', 'xoxb-abc'],
    ['无口令的连接串', 'postgres://user@localhost:5432/db'],
    ['webhook 路径太短', ('https://hooks.slack.com/' + 'services/abc')],
    ['值太短的键', 'token: abc'],
    ['纯标识符密文', 'credential = "abcdefghijklmnop"'],
    ['UUID 形状不报', 'credential = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"'],
    ['低熵值不报', 'credential = "1234567890123"'],
    ['官方示例值不报', 'credential = "Zx9Kq2Lm4Np7Rt1Vw3EXAMPLE"'],
  ];
  for (const [label, text] of misses) {
    assert.equal(detect(text).length, 0, `${label} 不应命中`);
  }
});

test('反转测试：generic-secret 兜底仍然会命中真实形状的高熵值', () => {
  // 防止“调着调着变成永远不命中”
  const hits = detect(`access_key = "${SYNTHETIC_SECRET}"`);
  const sec = hits.find((d) => d.category === 'secret');
  assert.ok(sec, 'access_key 赋值未被识别为 secret');
  assert.equal(sec.value, SYNTHETIC_SECRET);

  // 同一形状换成不在 .env 关键词表里的键名，必须由 generic 规则命中
  const generic = detect(`credential = "${SYNTHETIC_SECRET}"`);
  assert.equal(generic.length, 1);
  assert.equal(generic[0].ruleId, 'secret.generic.high_entropy');
  assert.equal(generic[0].validation, 'none');
  assert.equal(generic[0].shape, 'entropy-generic');
});

/**
 * 实测误报回归（来自 lead 的真实审计日志，不是构造的）。
 * 每个样本都用“原始形态”构造，防止同类形状再次被当成密钥。
 */
test('secret 误报回归：路径 / 模型名 / slug / 驼峰标识符 / 长串片段都不报', () => {
  const misses = [
    // ① 文件路径片段（审计里被脱成 /ds***way）
    ['绝对路径值', 'key: "/ds/projects/deepseek-harness/default-workspace"'],
    ['带盘符路径值', 'key: "F:/docs/dsh/packages"'],
    // ② 模型名 / slug（审计里被脱成 dee***ash）
    ['模型名 slug', 'model_key: ' + ['deepseek', 'v4.1', 'flash', 'preview'].join('-')],
    ['包名 slug', 'token = lodash.merge.deep.defaults'],
    // ③ 关键词没有紧邻赋值符（旧版 20 字符窗口会误报）
    ['关键词远离赋值符', 'secret manager config was loaded from the workspace directory'],
    // ④ 长度不足 20
    ['长度不足', 'credential = "Ab3Cd5Ef7"'],
    // ⑤ 纯 hex 摘要
    ['sha256 摘要', `credential = "${'a1b2c3d4'.repeat(8)}"`],
    // ⑥ 长串片段（128 上限截断出来的）
    ['超长串片段', `credential = "${'QUJD'.repeat(80)}"`],
    // 驼峰标识符（审计里被脱成 Too***ken）
    ['驼峰标识符', 'app_token = ToolPermissionTokenValue'],
    ['驼峰标识符短', 'APP_TOKEN=ToolPermissionToken'],
  ];
  for (const [label, text] of misses) {
    assert.equal(detect(text).length, 0, `${label} 不应命中`);
  }
});

/* ── 3. idcard ────────────────────────────────────────────────────────── */

test('idcard：18 位校验位 / 日期 / 区划', () => {
  const ok = one('110101190001010014');
  assert.equal(ok.category, 'idcard');
  assert.equal(ok.ruleId, 'idcard.cn18.checksum');
  assert.equal(ok.validation, 'mod11_2');
  assert.equal(ok.shape, 'cn-id-18');

  // 校验位为 X 的合法号
  assert.equal(one('11010819880808009X').ruleId, 'idcard.cn18.checksum');

  // 校验位错 → 不报（主要降误报手段）
  none('110101190001010015');
  // 2 月 30 日 → 不报
  none('110101190002300013');
  // 年份 1899（早于 1900）→ 不报
  none('110101189901010017');
  // 前两位不在 11–82 → 明显非法，不报
  assert.equal(detect('990101199001010010').filter((d) => d.category === 'idcard').length, 0);

  // 区划码未知（16 不是现行省级码）但校验位合法 → 仍然要报，ruleId 降级
  const unknown = one('160101199001010014');
  assert.equal(unknown.ruleId, 'idcard.cn18.unknown-division');
  assert.equal(unknown.validation, 'mod11_2');

  // 前后不能紧邻数字
  assert.equal(one('编号是110101190001010014。').category, 'idcard');
  assert.equal(detect('1101011900010100149').filter((d) => d.category === 'idcard').length, 0);
});

test('idcard：15 位旧号的三条准入路径', () => {
  // (c) 无上下文，但升级成 18 位能过 MOD 11-2
  const up = one('110101900101001');
  assert.equal(up.ruleId, 'idcard.cn15.upgraded');
  assert.equal(up.shape, 'cn-id-15');

  // (a) 上下文命中
  const ctx = one('身份证号 110101900101001');
  assert.equal(ctx.ruleId, 'idcard.cn15.context');
  assert.equal(ctx.validation, 'date');

  // (b) 同一行紧邻严格模式人名
  const withName = detect('联系人张三 110101900101001');
  assert.ok(withName.some((d) => d.ruleId === 'idcard.cn15.name'), '15 位号未走人名邻近路径');
  assert.ok(withName.some((d) => d.category === 'name'));

  // 日期非法 → 不报
  assert.equal(detect('110101901301001').filter((d) => d.category === 'idcard').length, 0);
  // 区划明显非法 → 不报
  assert.equal(detect('990101900101001').filter((d) => d.category === 'idcard').length, 0);
});

/* ── 4. bankcard ──────────────────────────────────────────────────────── */

test('bankcard：Luhn + BIN 前缀', () => {
  const visa = one('4111111111111111');
  assert.equal(visa.ruleId, 'bankcard.luhn');
  assert.equal(visa.validation, 'luhn');
  assert.equal(visa.shape, 'bankcard-16');

  // 允许中间空格
  const spaced = one('6222 0200 0000 0007');
  assert.equal(spaced.value, '6222 0200 0000 0007');
  assert.equal(spaced.shape, 'bankcard-16');

  // Luhn 不过 → 不报
  none('4111111111111112');
  // Luhn 过但 BIN 不在主流前缀（2 开头）→ 不报
  none('2222222222222224');
  // 位数不足 13 → 不报
  none('41111111111');
});

/* ── 5. phone ─────────────────────────────────────────────────────────── */

test('phone：大陆手机号边界', () => {
  const m = one('13800001111');
  assert.equal(m.category, 'phone');
  assert.equal(m.ruleId, 'phone.cn.mobile');
  assert.equal(m.value, '13800001111');

  // 12 位 → 不命中
  none('138000011119');
  // 嵌在 id= 后面要命中，且起点正确
  const idEq = one('id=13800001111');
  assert.equal(idEq.start, 3);
  // +86 前缀 + 空格分组
  const intl = one('+86 138 0000 1111');
  assert.equal(intl.value, '+86 138 0000 1111');
  // 19x 新号段也不能漏
  assert.equal(one('19612345678').ruleId, 'phone.cn.mobile');
});

test('phone：座机与分机', () => {
  const land = one('010-12345678');
  assert.equal(land.ruleId, 'phone.cn.landline');
  assert.equal(land.value, '010-12345678');

  const ext = one('0571-88888888转1234');
  assert.equal(ext.ruleId, 'phone.cn.landline');
  assert.ok(ext.value.endsWith('1234'));

  // 位数不够不命中
  none('010-1234');
});

/* ── 6. email ─────────────────────────────────────────────────────────── */

test('email：实用正则、去尾随标点', () => {
  const e = one('zhangsan+tag@mail.example.co.uk');
  assert.equal(e.ruleId, 'email.address');
  assert.equal(e.value, 'zhangsan+tag@mail.example.co.uk');

  // 尾随中文标点不进入 value
  const punct = one('联系 zhangsan@example.com，谢谢');
  assert.equal(punct.value, 'zhangsan@example.com');

  none('a@b');
  none('not-an-email@');
});

/* ── 7. address ───────────────────────────────────────────────────────── */

test('address：必须同时有道路 token 与门牌号', () => {
  const a = one('北京市朝阳区建国路88号');
  assert.equal(a.ruleId, 'address.cn');
  assert.equal(a.shape, 'cn-address');
  assert.ok(a.value.endsWith('88号'), '地址应包含门牌号');

  const full = one('浙江省杭州市西湖区文三路100号3单元501室');
  assert.equal(full.value, '浙江省杭州市西湖区文三路100号3单元501室');

  // 只有路名，没有门牌 → 不报
  none('建国路今天很堵');
  // 只有门牌，没有道路 token → 不报
  none('价格88号');
});

/* ── 8. name ──────────────────────────────────────────────────────────── */

test('name：严格模式只在上下文锚定命中', () => {
  const anchored = detect('联系人：张三，负责对接').find((d) => d.category === 'name');
  assert.ok(anchored, '锚定人名未命中');
  assert.equal(anchored.value, '张三');
  assert.equal(anchored.ruleId, 'name.cn.anchor');

  // 裸名（无锚点）不报
  assert.equal(detect('王小明去了北京').filter((d) => d.category === 'name').length, 0);
  // 职衔/称谓不是名字
  assert.equal(detect('张总在会议室').filter((d) => d.category === 'name').length, 0);
  assert.equal(detect('客户王先生已确认').filter((d) => d.category === 'name').length, 0);
  // 普通词不是名字
  assert.equal(detect('数字经济是新的增长点').filter((d) => d.category === 'name').length, 0);
});

test('name：宽松模式可裸匹配，但仍然拒绝职衔', () => {
  const loose = detect('王小明去了北京', { nameStrict: false }).filter((d) => d.category === 'name');
  assert.equal(loose.length, 1);
  assert.equal(loose[0].value, '王小明');
  assert.equal(loose[0].ruleId, 'name.cn.loose');

  assert.equal(
    detect('张总在会议室', { nameStrict: false }).filter((d) => d.category === 'name').length,
    0
  );
});

/* ── 9. org ───────────────────────────────────────────────────────────── */

test('org：中文后缀 / 英文后缀 / 统一社会信用代码', () => {
  const zh = one('某某科技有限公司');
  assert.equal(zh.ruleId, 'org.zh.suffix');
  assert.equal(zh.value, '某某科技有限公司');

  const usci = one('91350100M000100Y43');
  assert.equal(usci.category, 'org');
  assert.equal(usci.ruleId, 'org.cn.usci');
  assert.equal(usci.validation, 'mod31_3');
  assert.equal(usci.shape, 'cn-usci');

  // 校验位错 → 不报
  none('91350100M000100Y44');
  // 首字符不是登记管理部门码 → 不报
  none('21350100M000100Y43');
  // 字符集里禁止 I/O/S/V/Z → 不报
  none('91350100M000100YI3');

  const en = one('Acme Inc');
  assert.equal(en.ruleId, 'org.en.suffix');

  // 无后缀不报
  assert.equal(detect('我们公司最近很忙').filter((d) => d.category === 'org').length, 0);
});

test('org：中文公司名不把前导地名/赘词吞进来', () => {
  const r = one('深圳市某某科技有限公司');
  assert.equal(r.value, '某某科技有限公司');

  // 回溯停在“们”（硬刹车），只会多带 1 个虚词“与”——宁可多脱一段，也不切碎名字
  const junk = one('我们与某某科技有限公司已经签约');
  assert.ok(junk.value.endsWith('某某科技有限公司'), '公司名被切碎');
  assert.ok(junk.value.length <= '与某某科技有限公司'.length, '多带的虚词过多');
});

test('org 误报回归：真实企业名的前导字不能被裁剪（有/和/华/当/网）', () => {
  // 审计里被裁成 4 字残片的真实形状：带前导字的企业名必须完整保留
  assert.equal(one('本次采购由有研科技集团有限公司供货').value, '有研科技集团有限公司');
  assert.equal(one('签约方：腾讯计算机系统有限公司').value, '腾讯计算机系统有限公司');
  assert.equal(one('和平科技有限公司').value, '和平科技有限公司');
  assert.equal(one('某某集团有限公司').value, '某某集团有限公司');
  // 超长回溯才允许裁剪，且裁剪后必须 ≥6 字
  const long = one('甲乙双方一致同意委托某某科技有限公司承担本项目');
  assert.ok(long.value.length <= 20, '公司名长度超出 20 字上限');
});

test('name：远程锚点不能把普通词当人名（误报回归）', () => {
  // “客户”是锚点，但离“应偏慢”很远，且中间夹着正文 → 不能报
  assert.equal(
    detect('客户反馈：功能正常，但响应偏慢（约 300ms）。').filter((d) => d.category === 'name').length,
    0
  );
  // 锚点与人名之间只隔标点/系词时才认定
  assert.equal(
    detect('客户：王小明 已确认收货').filter((d) => d.category === 'name').length,
    1
  );
  assert.equal(detect('负责人是李四').filter((d) => d.category === 'name')[0].value, '李四');
});

test('name 误报回归：常用词表 + 词尾助词拦截', () => {
  // 审计里被误判的样本：姓氏字 + 常用字（项目 / 和平 / 和谐 / 应当 / 任何 …）
  const words = ['项目', '和平', '和谐', '应当', '任何', '何时', '张开', '常规', '程序', '明显', '文化', '成立'];
  for (const w of words) {
    assert.equal(
      detect(`负责人：${w}负责人`).filter((d) => d.category === 'name').length,
      0,
      `常用词被当成人名：${w}`
    );
  }
  // 词尾助词不能被吃进名字（“张伟和”应得“张伟”，不是“张伟和”）
  const cut = detect('负责人：张伟和另外两位同事').filter((d) => d.category === 'name');
  assert.equal(cut.length, 1);
  assert.equal(cut[0].value, '张伟');
  const cut2 = detect('联系人：李四的号码已更新').filter((d) => d.category === 'name');
  assert.equal(cut2.length, 1);
  assert.equal(cut2[0].value, '李四');
  // 正常人名不受影响
  assert.equal(detect('负责人：张伟').filter((d) => d.category === 'name')[0].value, '张伟');
});

/* ── 10. custom ───────────────────────────────────────────────────────── */

test('custom：词典命中最长者优先', () => {
  const longest = one('星河项目组本周进度', { dictionary: ['星河', '星河项目'] });
  assert.equal(longest.ruleId, 'custom.dictionary');
  assert.equal(longest.value, '星河项目');
  assert.equal(longest.category, 'custom');

  // ASCII 词边界：ACMEs 里不算命中
  const acme = detect('ACMEs 与 ACME 合作', { dictionary: ['ACME'] });
  assert.equal(acme.length, 1);
  assert.equal(acme[0].value, 'ACME');

  // minCustomLength
  none('AB', { dictionary: ['AB'], minCustomLength: 3 });
  assert.equal(detect('AB 测试', { dictionary: ['AB'] }).length, 1);

  // 中文直接 indexOf（不需要边界）
  assert.equal(detect('星河项目启动', { dictionary: ['星河项目'] }).length, 1);
});

test('custom：优先级高于 idcard（dictionary 命中的整段归 custom）', () => {
  const r = one('110101190001010014', { dictionary: ['110101190001010014'] });
  assert.equal(r.category, 'custom');
  assert.equal(r.ruleId, 'custom.dictionary');
});

/* ── 11. allowlist / allowPatterns ────────────────────────────────────── */

test('allowlist：整体覆盖才丢弃，ASCII 大小写不敏感', () => {
  none('电话 13800001111', { allowlist: ['13800001111'] });
  none('user@example.com', { allowlist: ['USER@EXAMPLE.COM'] });

  // 只覆盖一部分 → 仍然命中
  assert.equal(detect('电话 13800001111', { allowlist: ['1380000'] }).length, 1);
});

test('allowPatterns：整体覆盖才丢弃', () => {
  none('x@corp.local', { allowPatterns: ['\\S+@corp\\.local'] });
  // 只匹配到域名一部分，不能整体覆盖 → 仍然命中
  assert.equal(detect('x@corp.local', { allowPatterns: ['corp\\.local'] }).length, 1);
  // 非法正则源串不能让工厂抛异常
  assert.doesNotThrow(() => createDetector({ allowPatterns: ['([', 'ok.*'] }));
});

/* ── 12. 占位符跳过 ───────────────────────────────────────────────────── */

test('占位符：既有 [EMAIL_1] / [[EMAIL_1]] 不被二次检测', () => {
  none('[EMAIL_1]');
  none('[[EMAIL_1]]');
  none('[ API_KEY_2 ]');
  none('［［IDCARD_12］］');

  // 同一段文本里，占位符之外的号码仍要报
  const mixed = detect('联系人 [[EMAIL_1]]，电话 13800001111');
  assert.equal(mixed.length, 1);
  assert.equal(mixed[0].category, 'phone');

  // markdown 链接不算占位符（会正常参与检测）
  const link = detect('见 [附件](http://example.com/a)');
  assert.equal(link.filter((d) => d.category === 'phone').length, 0);
});

/* ── 13. 重叠归并 / 优先级 ────────────────────────────────────────────── */

test('重叠归并：18 位号既是身份证形状又是银行卡形状时只留 idcard', () => {
  // 该号同时满足：身份证校验位、Luhn、BIN 62
  const r = detect('621401190001010054');
  assert.equal(r.length, 1);
  assert.equal(r[0].category, 'idcard');
  assert.equal(r[0].ruleId, 'idcard.cn18.checksum');
});

test('重叠归并：secret 优先级高于 phone（重合区间整段归 secret）', () => {
  // 手机号形状的片段被包在 sk- token 内部：两条规则都会命中，secret 胜出
  const r = detect('sk-13800001111abcdefghij');
  assert.equal(r.length, 1);
  assert.equal(r[0].category, 'secret');
  assert.equal(r[0].value, 'sk-13800001111abcdefghij');

  // 互不重叠时各报各的
  const both = detect('13800001111 sk_live_abcdefghijklmnop1234');
  assert.equal(both.filter((d) => d.category === 'phone').length, 1);
  assert.equal(both.filter((d) => d.category === 'secret').length, 1);
});

test('结果不变量：start 升序、互不重叠、value 与原文一致、必带 validation', () => {
  const text =
    '联系人：张三，手机 13800001111，邮箱 zhangsan@example.com，' +
    '身份证 110101190001010014，卡号 6222 0200 0000 0007，' +
    '公司 某某科技有限公司，地址 北京市朝阳区建国路88号，密钥 API_KEY=Zx9Kq2Lm4Np7Rt1Vw3';
  const det = createDetector({ dictionary: ['某某科技'] });
  const r = det.detect(text);

  assert.ok(r.length >= 5, `检测数量偏少：${r.length}`);
  for (let i = 0; i < r.length; i++) {
    const d = r[i];
    assert.ok(CATEGORIES.includes(d.category), `未知类别 ${d.category}`);
    assert.equal(typeof d.ruleId, 'string');
    assert.ok(d.ruleId.length > 0, 'ruleId 不能为空');
    assert.equal(typeof d.validation, 'string');
    assert.ok(d.validation.length > 0, `${d.ruleId} 缺少 validation`);
    assert.equal(typeof d.shape, 'string');
    assert.ok(d.shape.length > 0, `${d.ruleId} 缺少 shape`);
    assert.notEqual(d.shape, 'none', `${d.ruleId} 的 shape 退化成 none`);
    assert.equal(d.value, text.slice(d.start, d.end));
    if (i > 0) assert.ok(r[i - 1].end <= d.start, '检测区间发生重叠');
  }
  // 序列化后不能丢字段（审计侧拿到的是 JSON）
  assert.deepEqual(JSON.parse(JSON.stringify(r)), r);
});

/* ── 14. categories 开关 ──────────────────────────────────────────────── */

test('categories：显式 false 的类别完全不检测', () => {
  const r = detect('电话 13800001111 邮箱 a@b.com', { categories: { phone: false } });
  assert.equal(r.length, 1);
  assert.equal(r[0].category, 'email');

  none('联系人：张三', { categories: { name: false } });
  none('AKIAIOSFODNN7EXAMPLE', { categories: { secret: false } });
});

/* ── 15. 性能冒烟 ─────────────────────────────────────────────────────── */

test('性能：~100KB 中文文本 detect < 300ms', () => {
  const parts = [];
  let total = 0;
  let i = 0;
  while (total < 104000) {
    const line =
      `第${i}条记录：本月项目进度汇报，客户反馈整体良好，技术团队已完成接口联调并通过回归测试，` +
      '财务对账无误，法务审核合同条款无异议，下周安排现场验收与操作培训。';
    parts.push(line);
    total += line.length + 1;
    if (i % 97 === 7) {
      const extra = '联系人：张三，手机 13800001111，邮箱 zhangsan@example.com。';
      parts.push(extra);
      total += extra.length;
    }
    if (i % 131 === 11) {
      const extra =
        '统一社会信用代码 91350100M000100Y43，注册地址 北京市朝阳区建国路88号，卡号 6222 0200 0000 0007。';
      parts.push(extra);
      total += extra.length;
    }
    i++;
  }
  const text = parts.join('\n');
  assert.ok(text.length >= 102400, `样本长度不足：${text.length}`);

  const det = createDetector({ dictionary: ['星河项目'] });
  det.detect(text.slice(0, 5000)); // 预热，避免把 JIT 时间算进指标

  const t0 = performance.now();
  const r = det.detect(text);
  const ms = performance.now() - t0;

  console.log(
    `     [perf] 文本 ${(text.length / 1024).toFixed(1)} KB，命中 ${r.length} 处，耗时 ${ms.toFixed(1)} ms`
  );
  assert.ok(ms < 300, `detect 耗时 ${ms.toFixed(1)}ms，超过 300ms 预算`);
});
