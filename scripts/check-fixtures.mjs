#!/usr/bin/env node
/**
 * Refuse to commit a complete token literal.
 *
 * This repository's test corpus has to look like real secrets for the detector
 * to be worth anything, and GitHub's secret scanning (correctly) treats any
 * complete token in the tree as a leak: it blocked the first push and then
 * emailed two post-push alerts. The durable fix is the rule the tests already
 * follow — assemble a token from fragments at runtime:
 *
 *     ['AWS key', 'AKIA' + 'IOSFODNN7EXAMPL' + 'E', 'secret.aws.access_key'],
 *
 * The detector sees the assembled value; the source contains no token.
 *
 * This guard scans the working tree for complete literals so a new fixture
 * cannot reintroduce the problem. It is intentionally broader than the rules
 * themselves: a false positive here costs one string split, a false negative
 * costs a public security alert.
 *
 * @module dsh-redact-gateway/scripts/check-fixtures
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SKIP_DIRS = new Set(['.git', 'node_modules', 'coverage']);
const TEXT = /\.(mjs|cjs|js|json|md|yml|yaml|txt|svg)$/i;

/** Every family the detection rules cover, plus the prefixes GitHub flags. */
const FAMILIES = [
  ['aws-key-id', /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g],
  // A bare 40-character base64 run is far too common to flag on its own, so the
  // AWS secret shape is only checked where a fixture would really put it.
  ['aws-secret-key', /(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*['"]?[A-Za-z0-9/+]{40}/gi],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['openai-key', /\bsk-(?:proj-|ant-|svcacct-|admin-|live-)?[A-Za-z0-9_-]{20,}/g],
  ['github-token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g],
  ['github-pat', /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g],
  ['gitlab-token', /\b(?:glpat|glrt)-[A-Za-z0-9_-]{20,}\b/g],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
  ['slack-app-token', /\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+\b/g],
  ['slack-webhook', /hooks\.slack\.com\/(?:services|workflows|triggers)\//g],
  ['tencent-secret-id', /\bAKID[A-Za-z0-9]{13,}\b/g],
  ['aliyun-access-key', /\bLTAI[A-Za-z0-9]{12,}\b/g],
  ['stripe-key', /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g],
  ['shopify-token', /\bshpat_[a-fA-F0-9]{32}\b/g],
  ['huggingface-token', /\bhf_[a-z0-9]{34}\b/g],
  ['azure-client-secret', /\b[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.-]{31,34}\b/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ['pem-private-key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
];

/** Every file worth scanning, depth-first. */
function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    const info = statSync(full);
    if (info.isDirectory()) walk(full, out);
    else if (TEXT.test(name)) out.push(full);
  }
  return out;
}

const findings = [];
for (const file of walk(ROOT)) {
  const text = readFileSync(file, 'utf8');
  for (const [name, pattern] of FAMILIES) {
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const line = text.slice(0, match.index).split('\n').length;
      findings.push({ file: relative(ROOT, file), line, family: name, length: match[0].length });
    }
  }
}

if (findings.length > 0) {
  console.error('check-fixtures: complete token literals found — split them into fragments:');
  for (const finding of findings) {
    console.error(`  ${finding.file}:${finding.line}  ${finding.family}  (${finding.length} chars)`);
  }
  console.error(
    '\nThe detector only needs the assembled value. Build it as prefix + body so the\n' +
      'source never contains a token GitHub (or any other scanner) would report.',
  );
  process.exit(1);
}

console.log('check-fixtures: no complete token literals in the tree');
