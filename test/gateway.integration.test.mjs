/**
 * Integration test for the `llm/stream` interception itself.
 *
 * It builds a miniature Host — a waterfall with exactly one listener (this
 * plugin's), a provider stub that records what it was actually asked to send,
 * and a session store — because the two behaviours that matter most here cannot
 * be tested in isolation:
 *
 * 1. the request the provider receives contains no original value, and
 * 2. the re-dispatch does not recurse (the guard makes the second pass call
 *    `next()` instead of masking again).
 *
 * The provider stub re-enters the waterfall exactly as `LlmRuntime` does, so a
 * broken guard shows up as an infinite loop rather than as a passing test.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { normalizeConfig } from '../lib/config.js';
import { Gateway } from '../lib/gateway.js';

const EMAIL = 'zhang.wei@example.com';
const PHONE = '13800001111';

/** A minimal Host: one waterfall hook, one provider stub, one session. */
function createHost({ cwd = 'D:/work/customers', onAdapter } = {}) {
  const hooks = new Map();
  const warnings = [];
  const seenRequests = [];
  const sessions = new Map([['session-1', { header: { cwd } }]]);

  const adapterStream = async function* adapterStream(options) {
    seenRequests.push(options);
    if (onAdapter !== undefined) return yield* onAdapter(options);
    yield { type: 'block-start', index: 0, blockType: 'text' };
    yield { type: 'text-delta', index: 0, text: '客户的邮箱是 ' };
    yield { type: 'text-delta', index: 0, text: '[EMA' };
    yield { type: 'text-delta', index: 0, text: `IL_1]，电话 [PHONE_1]。` };
    yield {
      type: 'block-end',
      index: 0,
      block: { type: 'text', text: '客户的邮箱是 [EMAIL_1]，电话 [PHONE_1]。' },
    };
    yield { type: 'finish', reason: { kind: 'stop' } };
  };

  /** Emulate `ctx.waterfall(this, 'llm/stream', options, next)`. */
  const dispatch = (options) => {
    const listeners = hooks.get('llm/stream') ?? [];
    let index = 0;
    const next = () => {
      const listener = listeners[index];
      index += 1;
      if (listener === undefined) return adapterStream(options);
      return listener(options, next);
    };
    return next();
  };

  const ctx = {
    logger: { info() {}, warn(message) { warnings.push(message); } },
    on(event, listener) {
      const list = hooks.get(event) ?? [];
      list.push(listener);
      hooks.set(event, list);
      return () => {};
    },
    get(name) {
      if (name === 'sessions') return sessions;
      return undefined;
    },
    effect(fn) {
      fn();
    },
  };

  const adapterCalls = [];
  ctx.llm = {
    async prepareCall(config) {
      adapterCalls.push(config);
      return {
        config: { ...config },
        stream(options) {
          return dispatch(options);
        },
      };
    },
  };

  return { ctx, dispatch, warnings, seenRequests, adapterCalls, sessions };
}

/** Build one frozen-ish request whose messages carry real data. */
function makeRequest(overrides = {}) {
  const message = {
    id: 'message-1',
    role: 'user',
    source: { kind: 'user' },
    content: [{ type: 'text', text: `联系 ${EMAIL} 或 ${PHONE}，身份证 11010519491231002X。` }],
  };
  return Object.freeze({
    provider: 'stub',
    model: 'stub-1',
    messages: Object.freeze([Object.freeze(message)]),
    sessionId: 'session-1',
    signal: new AbortController().signal,
    ...overrides,
  });
}

/** Run one request through the registration the plugin installed. */
async function run(gateway, host, request) {
  void gateway;
  const chunks = [];
  // Dispatch through the waterfall, exactly as the agent loop does: the
  // plugin's listener is the first hook, and its `next` advances to the
  // provider stub. Calling the listener directly would bypass that contract.
  for await (const chunk of host.dispatch(request)) chunks.push(chunk);
  return chunks;
}

/** Join every text delta, then apply the block-end text if one arrived. */
function renderedText(chunks) {
  const deltas = chunks
    .filter((chunk) => chunk.type === 'text-delta')
    .map((chunk) => chunk.text)
    .join('');
  const block = chunks.find((chunk) => chunk.type === 'block-end');
  return block !== undefined && block.block?.type === 'text' ? block.block.text : deltas;
}

function scratch() {
  const dir = mkdtempSync(join(tmpdir(), 'redact-gateway-it-'));
  return {
    dir,
    cleanup() {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        /* disposable */
      }
    },
  };
}

function makeGateway(host, space, configOverrides = {}) {
  const config = normalizeConfig({ dir: space.dir, promptHint: false, ...configOverrides });
  const gateway = new Gateway({
    ctx: host.ctx,
    config,
    paths: { root: space.dir, sessions: join(space.dir, 'sessions'), audit: join(space.dir, 'audit'), vaultTtlHours: 168 },
    warn: (message) => host.warnings.push(message),
    log: host.ctx.logger,
  });
  host.ctx.on('llm/stream', (options, next) => gateway.handleStream(options, next), { prepend: true, global: true });
  return gateway;
}

test('the provider receives placeholders, the user receives originals', async () => {
  const space = scratch();
  try {
    const host = createHost();
    const gateway = makeGateway(host, space);
    const chunks = await run(gateway, host, makeRequest());

    // Exactly one adapter call: the guard prevented a recursive re-dispatch.
    assert.equal(host.seenRequests.length, 1);
    const sent = JSON.stringify(host.seenRequests[0].messages);
    assert.equal(sent.includes(EMAIL), false, 'the raw email must not reach the provider');
    assert.equal(sent.includes(PHONE), false, 'the raw phone number must not reach the provider');
    assert.equal(sent.includes('11010519491231002X'), false, 'the raw ID must not reach the provider');
    assert.ok(sent.includes('[EMAIL_1]'));
    assert.ok(sent.includes('[PHONE_1]'));
    assert.ok(sent.includes('[IDCARD_1]'));

    const rendered = renderedText(chunks);
    assert.ok(rendered.includes(EMAIL), 'the response must be rehydrated');
    assert.ok(rendered.includes(PHONE));
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('the same value keeps one placeholder across separate requests', async () => {
  const space = scratch();
  try {
    const host = createHost();
    const gateway = makeGateway(host, space);
    await run(gateway, host, makeRequest());
    await run(gateway, host, makeRequest());

    assert.equal(host.seenRequests.length, 2);
    for (const request of host.seenRequests) {
      const sent = JSON.stringify(request.messages);
      assert.ok(sent.includes('[EMAIL_1]'));
      assert.equal(sent.includes('[EMAIL_2]'), false, 'the same value must reuse its placeholder');
    }
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('a request without sensitive data is passed through untouched', async () => {
  const space = scratch();
  try {
    const host = createHost();
    const gateway = makeGateway(host, space);
    const request = makeRequest({
      messages: Object.freeze([
        Object.freeze({
          id: 'message-2',
          role: 'user',
          source: { kind: 'user' },
          content: [{ type: 'text', text: '帮我重构这个函数。' }],
        }),
      ]),
    });
    await run(gateway, host, request);
    assert.equal(host.seenRequests.length, 1);
    assert.equal(host.adapterCalls.length, 0, 'no prepared call is made when nothing needs masking');
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('audit mode records detections but sends the original', async () => {
  const space = scratch();
  try {
    const host = createHost();
    const gateway = makeGateway(host, space, { mode: 'audit' });
    await run(gateway, host, makeRequest());

    const sent = JSON.stringify(host.seenRequests[0].messages);
    assert.ok(sent.includes(EMAIL), 'audit mode must not alter the request');
    const rows = gateway.audit.query({ category: 'email' });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].action, 'observe');
    assert.equal(JSON.stringify(rows).includes(EMAIL), false, 'the audit record must not contain the value');
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('a bypassed workspace is not touched and not audited', async () => {
  const space = scratch();
  try {
    const host = createHost({ cwd: 'D:/work/public-docs' });
    const gateway = makeGateway(host, space, {
      workspaces: [{ path: 'D:/work/public-docs', policy: 'bypass' }],
    });
    await run(gateway, host, makeRequest());
    const sent = JSON.stringify(host.seenRequests[0].messages);
    assert.ok(sent.includes(EMAIL));
    assert.equal(gateway.audit.query({}).length, 0);
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('a paused gateway sends the original and records why', async () => {
  const space = scratch();
  try {
    const host = createHost();
    const gateway = makeGateway(host, space);
    gateway.pause(60_000);
    await run(gateway, host, makeRequest());
    assert.ok(JSON.stringify(host.seenRequests[0].messages).includes(EMAIL));
    const rows = gateway.audit.query({ action: 'pause-skip' });
    assert.equal(rows.length, 1);
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('a failing provider call surfaces as one terminal error chunk', async () => {
  const space = scratch();
  try {
    const host = createHost({
      onAdapter: async function* failing() {
        throw new Error('network down');
      },
    });
    const gateway = makeGateway(host, space);
    const chunks = await run(gateway, host, makeRequest());
    const finish = chunks.find((chunk) => chunk.type === 'finish');
    assert.ok(finish !== undefined);
    assert.equal(finish.reason.kind, 'error');
    assert.equal(finish.reason.failure.code, 'PROVIDER_FAILED');
    // A provider failure is not a redaction block: it must not be counted as one.
    assert.equal(gateway.state().totals.blocked, 0);
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('tool-call arguments are masked outbound and restored at block end', async () => {
  const space = scratch();
  try {
    const host = createHost({
      onAdapter: async function* toolCall() {
        const args = JSON.stringify({ to: 'zhang.wei@example.com', body: 'hi' });
        yield { type: 'block-start', index: 0, blockType: 'tool-call' };
        yield { type: 'tool-call-delta', index: 0, id: 'call-1', name: 'send', argumentsDelta: args };
        yield {
          type: 'block-end',
          index: 0,
          block: {
            type: 'tool-call',
            id: 'call-1',
            name: 'send',
            arguments: JSON.stringify({ to: '[EMAIL_1]', body: 'hi' }),
          },
        };
        yield { type: 'finish', reason: { kind: 'stop' } };
      },
    });
    const gateway = makeGateway(host, space);

    // A tool call whose arguments carry the real address: the provider must see
    // the placeholder in the outbound message, so build one that does.
    const request = makeRequest({
      messages: Object.freeze([
        Object.freeze({
          id: 'message-3',
          role: 'assistant',
          source: { kind: 'model', provider: 'stub', model: 'stub-1' },
          content: [
            {
              type: 'tool-call',
              id: 'call-0',
              name: 'send',
              arguments: JSON.stringify({ to: EMAIL, body: 'hi' }),
            },
          ],
        }),
      ]),
    });
    const chunks = await run(gateway, host, request);

    const sent = JSON.stringify(host.seenRequests[0].messages);
    assert.equal(sent.includes(EMAIL), false, 'tool-call arguments must be masked outbound');
    assert.ok(sent.includes('[EMAIL_1]'));

    const block = chunks.find((chunk) => chunk.type === 'block-end');
    assert.equal(block.block.arguments.includes('[EMAIL_1]'), false, 'the tool must execute on the original value');
    assert.equal(JSON.parse(block.block.arguments).to, EMAIL);
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});

test('the state surface is JSON-serializable and never carries a raw value', async () => {
  const space = scratch();
  try {
    const host = createHost();
    const gateway = makeGateway(host, space);
    await run(gateway, host, makeRequest());
    const state = gateway.state();
    const json = JSON.stringify(state);
    assert.equal(json.includes(EMAIL), false);
    assert.equal(json.includes(PHONE), false);
    assert.equal(state.session.placeholders, 3);
    assert.ok(state.recent.length >= 1);
    assert.ok(state.recent.every((entry) => typeof entry.mask === 'string' && entry.mask.includes('*')));
    gateway.dispose();
  } finally {
    space.cleanup();
  }
});
