/**
 * Unit tests for the parts of the gateway that do not need a model or a Host:
 * config resolution, the encrypted vault, the streaming rehydrator, and the
 * audit log. Run with `node --test test/`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { normalizeConfig, resolveWorkspacePolicy } from '../lib/config.js';
import { Vault, ensureMasterKey } from '../lib/vault.js';
import { Rehydrator, rehydrateText } from '../lib/stream.js';
import { AuditLog, ensureFingerprintKey, maskValue } from '../lib/audit.js';

/** Create a throwaway directory for one test. */
function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'redact-gateway-test-'));
  return {
    dir,
    cleanup() {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* Windows may still hold a handle; the temp dir is disposable anyway */
      }
    },
  };
}

test('config: defaults are protective', () => {
  const config = normalizeConfig({});
  assert.equal(config.mode, 'enforce');
  assert.equal(config.onError, 'block');
  assert.equal(config.promptHint, true);
  assert.equal(config.categories.idcard, true);
  assert.deepEqual(config.placeholder, { open: '[', close: ']' });
});

test('config: rejects nonsense enums and keeps the safe default', () => {
  const config = normalizeConfig({ mode: 'whatever', onError: 'yolo', minCustomLength: -3 });
  assert.equal(config.mode, 'enforce');
  assert.equal(config.onError, 'block');
  assert.equal(config.minCustomLength, 2);
});

test('config: unusable placeholder delimiters fall back', () => {
  const warnings = [];
  const config = normalizeConfig({ placeholder: { open: ']]', close: ']]' } }, (message) => warnings.push(message));
  assert.deepEqual(config.placeholder, { open: '[', close: ']' });
  assert.equal(warnings.length, 1);
});

test('config: workspace policies resolve by longest prefix', () => {
  const config = normalizeConfig({
    workspaces: [
      { path: 'D:/work/public', policy: 'bypass' },
      { path: 'D:/work/public/payroll', policy: 'enforce', dictionary: ['薪级表'] },
    ],
  });

  const open = resolveWorkspacePolicy(config, 'D:\\work\\public\\docs');
  assert.equal(open.policy, 'bypass');
  assert.equal(open.mode, 'off');

  const nested = resolveWorkspacePolicy(config, 'D:/work/public/payroll/2026');
  assert.equal(nested.policy, 'enforce');
  assert.equal(nested.mode, 'enforce');
  assert.deepEqual(nested.dictionary, ['薪级表']);

  const outside = resolveWorkspacePolicy(config, 'D:/other');
  assert.equal(outside.policy, 'enforce');
  assert.equal(outside.matched, '');
});

test('config: a workspace may narrow categories without restating them', () => {
  const config = normalizeConfig({
    workspaces: [{ path: 'D:/work/x', categories: { name: false, address: false } }],
  });
  const policy = resolveWorkspacePolicy(config, 'D:/work/x');
  assert.equal(policy.categories.name, false);
  assert.equal(policy.categories.address, false);
  assert.equal(policy.categories.idcard, true);
});

test('vault: the same value gets the same placeholder and counts hits', () => {
  const space = scratch();
  try {
    const { key } = ensureMasterKey(space.dir);
    const vault = Vault.open({ dir: space.dir, sessionId: 'session-1', key });
    vault.setDelimiters({ open: '[', close: ']' });

    const first = vault.placeholder('email', 'zhang@example.com');
    const second = vault.placeholder('email', 'zhang@example.com');
    assert.equal(first.placeholder, '[EMAIL_1]');
    assert.equal(first.created, true);
    assert.equal(second.placeholder, '[EMAIL_1]');
    assert.equal(second.created, false);

    const other = vault.placeholder('phone', '13800001111');
    assert.equal(other.placeholder, '[PHONE_1]');

    vault.flush(true);
    vault.dispose();
  } finally {
    space.cleanup();
  }
});

test('vault: the mapping survives a restart under the same key', () => {
  const space = scratch();
  try {
    const { key } = ensureMasterKey(space.dir);
    const first = Vault.open({ dir: space.dir, sessionId: 'session-2', key });
    first.setDelimiters({ open: '[', close: ']' });
    first.placeholder('idcard', '11010519491231002X');
    assert.equal(first.flush(true), true);
    first.dispose();

    const second = Vault.open({ dir: space.dir, sessionId: 'session-2', key });
    second.setDelimiters({ open: '[', close: ']' });
    assert.equal(second.resolve('[IDCARD_1]'), '11010519491231002X');
    assert.equal(second.entries().length, 1);

    const onDisk = readFileSync(join(space.dir, 'sessions', 'session-2.vault'), 'utf8');
    assert.equal(onDisk.includes('11010519491231002X'), false, 'the mapping must not be plaintext on disk');
    second.dispose();
  } finally {
    space.cleanup();
  }
});

test('vault: a mapping moved onto another session refuses to decrypt', () => {
  const space = scratch();
  try {
    const { key } = ensureMasterKey(space.dir);
    const first = Vault.open({ dir: space.dir, sessionId: 'session-a', key });
    first.setDelimiters({ open: '[', close: ']' });
    first.placeholder('email', 'a@b.com');
    first.flush(true);
    first.dispose();

    const source = join(space.dir, 'sessions', 'session-a.vault');
    writeFileSync(join(space.dir, 'sessions', 'session-b.vault'), readFileSync(source));

    const warnings = [];
    const stolen = Vault.open({ dir: space.dir, sessionId: 'session-b', key, warn: (m) => warnings.push(m) });
    assert.equal(stolen.entries().length, 0);
    assert.equal(stolen.resolve('[EMAIL_1]'), undefined);
    assert.ok(warnings.some((message) => message.includes('could not be decrypted')));
    // The unreadable file is preserved for recovery rather than deleted.
    assert.ok(readdirSync(join(space.dir, 'sessions')).some((name) => name.includes('unreadable')));
    stolen.dispose();
  } finally {
    space.cleanup();
  }
});

test('vault: a wrong key is detected, not silently trusted', () => {
  const space = scratch();
  try {
    const { key } = ensureMasterKey(space.dir);
    const vault = Vault.open({ dir: space.dir, sessionId: 'session-c', key });
    vault.setDelimiters({ open: '[', close: ']' });
    vault.placeholder('phone', '13900002222');
    vault.flush(true);
    vault.dispose();

    const wrong = Vault.open({ dir: space.dir, sessionId: 'session-c', key: Buffer.alloc(32, 3), warn: () => {} });
    assert.equal(wrong.resolve('[PHONE_1]'), undefined);
    wrong.dispose();
  } finally {
    space.cleanup();
  }
});

test('vault: memory-only mode still masks and restores', () => {
  const vault = Vault.open({ dir: '', sessionId: 'memory', key: Buffer.alloc(32, 1), degraded: true });
  vault.setDelimiters({ open: '[', close: ']' });
  const { placeholder } = vault.placeholder('secret', 'sk-live-abcdefghijklmnop');
  assert.equal(vault.resolve(placeholder), 'sk-live-abcdefghijklmnop');
  assert.equal(vault.flush(true), false);
});

test('stream: a placeholder split across deltas is restored, not leaked', () => {
  const resolve = (category, index) => (category === 'EMAIL' && index === 1 ? 'zhang@example.com' : undefined);
  const rehydrator = new Rehydrator({ resolve });

  const head = rehydrator.push('联系邮箱 [EMA');
  assert.equal(head, '联系邮箱 ');
  const tail = rehydrator.push('IL_1] 即可');
  assert.equal(tail, 'zhang@example.com 即可');
  assert.equal(rehydrator.flush(), '');
  assert.equal(rehydrator.replaced, 1);
});

test('stream: altered delimiters are still restored and counted as repairs', () => {
  const resolve = (category, index) => (category === 'PHONE' && index === 2 ? '13800001111' : undefined);
  for (const text of ['[[PHONE_2]]', '[ phone - 2 ]', '［PHONE_2］', '(PHONE_2)', '{PHONE_2}']) {
    const rehydrator = new Rehydrator({ resolve });
    const out = rehydrator.push(text) + rehydrator.flush();
    assert.equal(out, '13800001111', `failed for ${text}`);
    assert.equal(rehydrator.replaced, 1);
  }
});

test('stream: an invented placeholder is passed through and counted', () => {
  const resolve = () => undefined;
  const rehydrator = new Rehydrator({ resolve });
  const out = rehydrator.push('客户是 [ORG_2] 的') + rehydrator.flush();
  assert.equal(out, '客户是 [ORG_2] 的');
  assert.equal(rehydrator.unknown, 1);
});

test('stream: markdown links are never held back', () => {
  const resolve = () => undefined;
  const rehydrator = new Rehydrator({ resolve });
  assert.equal(rehydrator.push('[文档](https://example.com/a)'), '[文档](https://example.com/a)');
  assert.equal(rehydrator.push(' 结尾'), ' 结尾');
});

test('stream: an unterminated bracket run larger than the hold window is released', () => {
  const resolve = () => undefined;
  const rehydrator = new Rehydrator({ resolve });
  const text = `[${'x'.repeat(80)}`;
  assert.equal(rehydrator.push(text), text);
});

test('stream: disabled rehydration passes every delta straight through', () => {
  const resolve = () => 'should-not-appear';
  const rehydrator = new Rehydrator({ resolve, enabled: false });
  assert.equal(rehydrator.push('[EMAIL_1]'), '[EMAIL_1]');
  assert.equal(rehydrator.flush(), '');
});

test('stream: rehydrateText repairs a completed string', () => {
  const resolve = (category, index) => (category === 'IDCARD' && index === 1 ? '11010519491231002X' : undefined);
  const result = rehydrateText('身份证 [[IDCARD_1]] 已登记', resolve);
  assert.equal(result.text, '身份证 11010519491231002X 已登记');
  assert.equal(result.replaced, 1);
});

test('audit: records chain and verification detects a rewrite', () => {
  const space = scratch();
  try {
    const log = AuditLog.open({
      dir: join(space.dir, 'audit'),
      fingerprintKey: ensureFingerprintKey(space.dir),
      retentionDays: 90,
      mask: true,
    });

    log.record({ sessionId: 's1', category: 'email', ruleId: 'email.basic', placeholder: '[EMAIL_1]', mask: 'a***@b.com', valueFp: log.fingerprint('a@b.com'), valueShape: 'email' });
    log.record({ sessionId: 's1', category: 'phone', ruleId: 'phone.cn.mobile', placeholder: '[PHONE_1]', mask: '138****1111', valueFp: log.fingerprint('13800001111'), valueShape: 'cn-mobile' });
    log.record({ sessionId: 's1', category: 'email', ruleId: 'email.basic', placeholder: '[EMAIL_1]', mask: 'a***@b.com', valueFp: log.fingerprint('a@b.com'), valueShape: 'email' });

    assert.equal(log.verifyChain().ok, true);
    assert.equal(log.query({ category: 'phone' }).length, 1);
    assert.equal(log.query({ limit: 2 }).length, 2);

    const files = readdirSync(join(space.dir, 'audit')).filter((name) => name.endsWith('.jsonl'));
    const file = join(space.dir, 'audit', files[files.length - 1]);
    const lines = readFileSync(file, 'utf8').trimEnd().split('\n');
    lines[1] = lines[1].replace('"mask":"138', '"mask":"137');
    writeFileSync(file, `${lines.join('\n')}\n`);

    const verification = log.verifyChain();
    assert.equal(verification.ok, false);
    assert.equal(verification.brokenAt, 2);
  } finally {
    space.cleanup();
  }
});

test('audit: fingerprints are keyed and stable within one installation', () => {
  const space = scratch();
  try {
    const key = ensureFingerprintKey(space.dir);
    const log = AuditLog.open({ dir: join(space.dir, 'audit'), fingerprintKey: key, retentionDays: 90, mask: true });
    const first = log.fingerprint('13800001111');
    const second = log.fingerprint('13800001111');
    assert.equal(first, second);
    assert.equal(first.length, 32);
    assert.equal(log.fingerprint('13800001112') === first, false);
    // The fingerprint must not be a plain hash of the value.
    assert.equal(createHash('sha256').update('13800001111').digest('hex').slice(0, 32) === first, false);
  } finally {
    space.cleanup();
  }
});

test('audit: CSV export is BOM-prefixed, quoted, and injection-safe', () => {
  const space = scratch();
  try {
    const log = AuditLog.open({
      dir: join(space.dir, 'audit'),
      fingerprintKey: ensureFingerprintKey(space.dir),
      retentionDays: 90,
      mask: true,
    });
    log.record({
      sessionId: 's1',
      category: 'org',
      ruleId: 'org.suffix',
      placeholder: '[ORG_1]',
      mask: '=HYPERLINK("http://evil")',
      valueFp: 'abc',
      valueShape: 'org',
      count: 2,
    });
    const outPath = join(space.dir, 'out.csv');
    const result = log.exportCsv({}, outPath);
    assert.equal(result.rows, 1);
    assert.equal(result.csv.startsWith('\uFEFF'), true);
    assert.ok(result.csv.includes('"\'=HYPERLINK'));
    assert.ok(result.csv.includes('"prev_hash"'));
    assert.equal(existsSync(outPath), true);
  } finally {
    space.cleanup();
  }
});

test('audit: masks keep a recognisable shape without the value', () => {
  assert.equal(maskValue('zhang.wei@example.com', 'email'), 'z***@example.com');
  assert.equal(maskValue('13800001111', 'phone'), '138*****111');
  assert.equal(maskValue('abc', 'custom'), 'a**');
  assert.equal(maskValue('11010519491231002X', 'idcard'), '110************02X');
});
