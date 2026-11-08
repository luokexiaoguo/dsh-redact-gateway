# Egress redaction gateway (`dsh-redact-gateway`)

English | [中文](README.zh.md)

> DSH sends prompts, tool results and attachments to a model provider **verbatim**.
> This plugin intercepts each request before it leaves the machine, replaces
> identity numbers, phone numbers, bank cards, emails, addresses, customer names
> and secrets with numbered placeholders, sends the masked copy, then restores
> the response. The user reads the original text; the model never saw it.

Built for small teams that must hand internal documents, code and customer data
to a cloud model, where the security review stops at exactly one question: *does
our data leave?* Unlike "a redaction tool the model has to remember to call",
this enforces itself at the transport boundary — the model has no choice and
there is no "forgot to call it" failure mode.

---

## 1. What it actually does

```
session log (originals — this is what the user reads)
        │  deriveMessages()
        ▼
   frozen request ──► llm/stream intercept ──► detect + replace ──► audit ──► encrypted mapping on disk
                                        │
                                        ▼
                              model provider (sees only [EMAIL_1])
                                        │
                                        ▼
                              streaming rehydration (placeholder → original)
                                        │
                                        ▼
                     assistant message committed (originals) ──► user reads originals
```

Three properties follow:

1. **The model side cannot be bypassed.** The interception point is the
   `llm/stream` waterfall, not a tool. Every model call — main conversation,
   subagents, session titles, compaction — passes through it.
2. **The user side is lossless.** The session log keeps originals; placeholders
   exist only in the outbound copy. Restoration needs no guessing and no history
   rewriting.
3. **It is auditable.** Every substitution writes one record with category, rule,
   placeholder, partial mask, keyed fingerprint, and a hash-chain link. Editing or
   deleting a line breaks `verify`.

### This is pseudonymisation, not anonymisation

Placeholders are reversible and the mapping lives on this machine, so under PIPL
Art. 73 this is **去标识化 (pseudonymisation)**, not 匿名化 (anonymisation): the
mapping is still personal data and stays in scope. The plugin provides PIPL
Art. 51 technical measures (encryption, de-identification, access control); it is
**not** an exemption from personal-data obligations. Do not describe it as
anonymisation in a security review.

---

## 2. Install

```bash
# directory install (development / internal distribution)
#   plugin_manager action=install_bundle target=<absolute path to this package>

# npm (once published)
#   plugin_manager action=install_bundle target=dsh-redact-gateway
```

Then open **Settings → Egress redaction gateway** to see state, switch modes,
toggle categories, and export the audit CSV. The plugin row's own configuration
lives in the profile's `cordis.patch.yml` (section 5).

> After installing, send one message containing test data (for example a made-up
> phone number) and confirm the counter on the settings page increases. A counter
> that stays at zero means interception is not active — investigate before use.

---

## 3. What it detects

| Category | Placeholder | Validation | Main false-positive risk |
| --- | --- | --- | --- |
| `secret` | `[SECRET_1]` | vendor prefixes + entropy + keyword proximity | hashes/UUIDs (built-in allowlist) |
| `idcard` | `[IDCARD_1]` | GB 11643 ISO 7064 MOD 11-2 + real date + division code | 18-digit order numbers |
| `bankcard` | `[BANKCARD_1]` | Luhn + major IIN ranges | Luhn-valid order numbers/IMEIs |
| `phone` | `[PHONE_1]` | prefix + boundaries | rare |
| `email` | `[EMAIL_1]` | practical regex + structure checks | rare |
| `address` | `[ADDR_1]` | province/city/district + road + door number | addresses in legal/news text |
| `name` | `[NAME_1]` | surname table + context anchoring (strict by default) | bare matching would flag "张总" (off by default) |
| `org` | `[ORG_1]` | GB 32100 unified social credit code + name suffixes | common words ("建设", "东方") |
| `custom` | `[TERM_1]` | literal, longest match | very short terms |

**Priority / overlap**: `secret > custom > idcard > bankcard > phone > email >
org > address > name`. The eleven digits inside an ID card are never also read as
a phone number.

**The custom dictionary is the highest-ROI switch.** Put customer lists, project
codenames and internal product names in `dictionary` (or let the agent add them
with `redact_dictionary`). It is far more reliable than any heuristic for names
and organizations.

### Placeholder format

The default is `[EMAIL_1]` — single brackets, upper-case category, underscore,
incrementing number. A measured round-trip study (arXiv:2610.34012) found this
shape survives best: models rewrite `<Name_1>` into `[Name_1]` themselves, and
`[[…]]` collides with wiki-link syntax.

Rehydration is **tolerant**: `[[EMAIL_1]]`, `[ email - 1 ]`, `［EMAIL_1］`,
`(EMAIL_1)` and `{EMAIL_1}` all restore, and are counted as repairs. Placeholders
the model **invents** (an `[ORG_9]` that was never issued) are never guessed at —
they pass through untouched and are counted, which is the only safe behaviour.

---

## 4. Workspace allowlists and exemptions

Matching is **longest-prefix** on the session's working directory, so a nested
directory can re-enable redaction inside an exempted tree.

```yaml
workspaces:
  # public documentation: nothing is masked, nothing is logged
  - path: 'D:/work/public-docs'
    policy: bypass

  # a sensitive nested tree inside it: forced back on
  - path: 'D:/work/public-docs/payroll'
    policy: enforce
    dictionary: ['salary bands', 'comp review 2026']

  # observe only, for a rollout period
  - path: 'D:/work/legacy-crm'
    policy: audit
```

`policy`: `enforce` (default), `audit` (record only, no substitution), `bypass`
(skip entirely, not even an audit line).

---

## 5. Configuration reference

```yaml
- id: redact-gateway
  name: dsh-redact-gateway
  config:
    mode: enforce              # enforce | audit | off
    onError: block             # block | pass (see section 8)

    categories:                # global category switches
      name: false              # turn off the name heuristic if it is noisy
      address: true

    dictionary: []             # custom sensitive terms
    allowlist:
      values:                  # never masked, literal
        - 'example.com'
        - '13800000000'
      patterns:                # never masked, regex source
        - '@example\.(com|org)$'

    minCustomLength: 2
    nameStrict: true           # names only when context-anchored
    promptHint: true           # add the "keep placeholders verbatim" system note
    streamRehydrate: true      # incremental restore (off = restore at block end)
    vaultTtlHours: 168         # session mapping retention

    workspaces: []             # see section 4
    dir: ''                    # data directory, default <DSH_HOME>/redact-gateway

    audit:
      retentionDays: 90
      mask: true               # include the partial mask column
      dedupe: true             # one row per distinct value per session
      dir: ''                  # default <data dir>/audit
```

Changes made on the settings page apply to the running process first, then are
written back into the profile configuration (the write restarts the plugin; that
is expected).

---

## 6. Where data lands

```
<DSH_HOME>/redact-gateway/
├── master.key                      # 32-byte AES master key (0600)
├── fingerprint.key                 # audit HMAC key (0600, separate from the above)
├── sessions/<sessionId>.vault      # AES-256-GCM encrypted placeholder mapping
├── audit/YYYY-MM.jsonl             # append-only audit with a hash chain
├── audit/stats.json                # lifetime counters
└── exports/redact-audit-*.csv      # exported CSVs
```

**Two keys is deliberate.** `master.key` can decrypt the mapping (reversible);
`fingerprint.key` can only compute non-invertible fingerprints. The exported CSV
contains only the latter, so it is safe to circulate internally — possessing the
CSV does not let you recover originals.

**Why the audit does not use "salt + hash":** the phone-number space is a few
billion entries — seconds on one GPU; the Chinese ID space is ~10¹¹ — minutes. A
salted hash is effectively no protection for de-identification. This plugin uses
a **keyed HMAC**, which is not enumerable without the key.

**Key rotation:** set `DSH_REDACT_KEY` (32 bytes base64/hex) to override
`master.key` for centrally managed deployments. After a rotation, old mappings no
longer decrypt; they are renamed to `*.vault.unreadable-<ts>` rather than deleted.
Rotate at a session boundary.

---

## 7. Audit CSV

21 columns, UTF-8 with BOM, opens directly in Excel:

```
seq, timestamp_utc, timestamp_local, session_id, workspace_fp, provider, model, purpose,
direction, action, category, rule_id, placeholder, mask, value_fp, value_shape,
validation, occurrences, outcome, prev_hash, record_hash
```

- **Never contains an original value**, a file name, or prompt text.
- `workspace_fp` is an HMAC of the working directory: a reviewer can tell "same
  project", but a leaked CSV does not name projects.
- `value_fp` is the first 128 bits of an HMAC: correlates the same ID across
  records, cannot be reversed.
- `mask` looks like `138*****111`: enough to recognise the data type, not enough
  to reuse.
- **CSV formula injection** is neutralized (cells starting with `=` `+` `-` `@`
  get a leading `'` and every cell is quoted).
- **Deduplication is on by default** (`audit.dedupe`): a long conversation
  re-sends its whole history on every request, so per-occurrence rows would turn
  seventy distinct findings into nearly a thousand identical lines. The
  `occurrences` column keeps the real count; set it to `false` when per-request
  evidence is required.

Export via the settings page, `/redact export [days]`, or the
`redact_export_csv` tool. Verify integrity with `/redact verify`, which recomputes
the whole chain and reports the first break.

---

## 8. Failure policy: why the default is "block"

If the redaction path itself fails (disk unwritable, encryption error, detector
throw), `onError: block` fails **that request** — not one byte of the original is
sent — and the error names the gateway as the blocker.

That is the correct default for a security product: "protection failed, so the
data went out anyway" is no protection. The cost is the occasional opaque error.
Diagnose with the `redact-gateway:` prefix in the DSH log; setting `onError: pass`
temporarily lets requests through (still audited), but restoring it must be
treated as a required follow-up.

A second hard stop: **the mapping must be durable before dispatch.** If the
mapping cannot be written, the request is blocked — a placeholder that leaves
without its mapping can never be restored, and the user would be left reading
`[EMAIL_1]`.

---

## 9. Tools and commands

Agent tools (**nothing returned to the model contains an original value**):

| Tool | Purpose |
| --- | --- |
| `redact_status` | mode, workspace policy, category switches, session counts |
| `redact_preview` | which spans a text would mask (category/rule/placeholder/offset only, **never the matched value**) |
| `redact_audit` | recent audit rows (mask + fingerprint) |
| `redact_export_csv` | write the CSV and return its path |
| `redact_dictionary` | list / add / remove custom sensitive terms |

User-only slash command:

```
/redact                    status
/redact pause [minutes]    pause temporarily (default 30), audited as pause-skip
/redact resume             resume
/redact export [days]      export the last N days
/redact verify             verify the audit hash chain
```

Pausing is **user-only** by design: no agent tool can disable protection.

---

## 10. Known limits (state these to a reviewer)

- **Text only.** Image and attachment bytes still leave the machine; DSH has
  already replaced file references with handle text, but text inside screenshots
  or scans is out of scope. Restrict image uploads separately if that matters.
- **Streaming tool arguments are not rehydrated mid-stream.** Substituting inside
  a JSON fragment would break quoting, so placeholders are restored at block end.
  Tool execution receives originals; only the streaming preview may briefly show a
  placeholder.
- **Names and addresses are heuristics.** Both miss and over-match. Use the custom
  dictionary as the primary control and the heuristics as a backstop.
- **Models rewrite placeholders.** This is a measured failure mode, not a bug:
  they change brackets, add spaces, rename tokens, and invent new ones. What can
  be repaired is repaired (counted as `repair`); the rest is left verbatim and
  counted. `promptHint` helps significantly but cannot eliminate it.
- **Do not stack two redacting gateways.** If the organization already runs an
  egress gateway, run this one in `audit` mode for visibility instead of masking
  twice (placeholders would collide).
- **Any `verify`-style feature is itself egress.** This plugin never validates a
  captured secret against its provider.

---

## 11. Compliance mapping

| Requirement | Measure |
| --- | --- |
| PIPL Art. 51 — encryption / de-identification / access control | AES-256-GCM mapping with session-bound AAD; audit stores HMAC only |
| PIPL Art. 47 — deletion | mapping TTL (`vaultTtlHours`) + delete-the-file crypto-shredding |
| PIPL Arts. 55/56 — cross-border transfer assessment and records | audit CSV is the processing record (time, category, workspace fingerprint, provider, model) |
| PIPL Art. 73 — pseudonymisation vs anonymisation | explicitly declared as pseudonymisation; mapping treated as personal data |
| GDPR Art. 30 — records of processing | CSV covers categories, recipients (provider/model), timing, erasure limits |
| GDPR Art. 32 — pseudonymisation as a safeguard | placeholders + separated keys + hash chain |

Retention: audit hot 90 days, archive 3 years (the PIPL Art. 56 floor for impact
assessments). Session mappings default to 7 days — they only serve live
restoration, so shorter is safer.

---

## 12. Layout

```
index.js            # apply(): composition and lifecycle
lib/config.js       # config normalization, workspace policy resolution
lib/rules.js        # detection engine (pure functions, independently testable)
lib/redact.js       # request masking (immutable rebuild)
lib/stream.js       # streaming rehydration (cross-chunk, tolerant, repair counter)
lib/vault.js        # AES-256-GCM session mapping
lib/audit.js        # audit log, hash chain, CSV export
lib/gateway.js      # llm/stream orchestration and failure policy
lib/http.js         # settings page routes (connection service + same-origin)
lib/tools.js        # agent tools
client/client.js    # settings page UI
test/               # node:test suites (node test/xxx.test.mjs)
```

## 13. Development

```bash
cd packages/redact-gateway
node test/units.test.mjs       # config / vault / rehydration / audit
node test/rules.test.mjs       # detection rules
```

> In a sandboxed shell run `node <file>` directly, not `node --test`: the test
> runner spawns a child process, which a restricted sandbox refuses with `EPERM`.
