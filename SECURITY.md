# Security policy

This is a data-loss-prevention component, so two different conversations matter:
**reporting a vulnerability in this plugin**, and **understanding what it does and
does not protect against** before you rely on it.

## Reporting a vulnerability

Please do not open a public issue for anything that weakens the protection this
plugin claims. Use GitHub's private advisory form instead:

<https://github.com/luokexiaoguo/dsh-redact-gateway/security/advisories/new>

Useful reports name the affected version, the category or rule involved (for
example `phone.cn.mobile`, or the vault file format), and the smallest input that
reproduces the problem. A detection **false negative** — a value of a supported
category that reaches the provider unmasked — is a security report, not a bug
report. False positives are ordinary issues; open those publicly.

Please allow a reasonable window before disclosure. There is no paid bounty.

## What this plugin protects against

- A model provider, or anything between this machine and that provider, reading
  identity numbers, phone numbers, bank cards, email addresses, addresses,
  customer names or secrets that appear in a prompt, a tool result, or an
  assistant-visible part of the request.
- Silent operation: every substitution is written to a tamper-evident audit log
  that can be exported as CSV.

## What it does not protect against

State these to a reviewer; none of them is a bug.

1. **This is pseudonymisation, not anonymisation.** Placeholders are reversible
   and the mapping lives on this machine. Under PIPL Art. 73 (and GDPR Art. 4(5))
   the mapping is still personal data. Do not use this plugin as an argument that
   data stopped being personal data.
2. **The mapping table is only as safe as the machine.** The mapping is encrypted
   with AES-256-GCM, and the key sits beside it in a `0600` file (or comes from
   `DSH_REDACT_KEY`). Anyone who can read the whole profile directory as your user
   can read both. It protects against copying the vault alone, a backup of the
   audit directory, or the exported CSV — not against an attacker who already has
   your account.
3. **Text only.** Image bytes, audio and other binary attachments still leave the
   machine. Text rendered inside a screenshot or a scan is not inspected.
4. **Heuristics can miss.** `name`, `address` and `org` detection is deliberately
   conservative and will both miss and over-match. Treat the custom dictionary as
   the primary control.
5. **Models mangle placeholders.** They change brackets, add spaces, rename
   tokens, and invent new ones. What can be repaired is repaired; the rest stays
   verbatim and is counted. `promptHint` reduces it, it does not eliminate it.
6. **A lost mapping cannot be un-masked.** If a session mapping is deleted, expires
   (`vaultTtlHours`) or the key rotates, placeholders already in the conversation
   can no longer be restored. The model may then write those placeholder tokens
   into files it creates. This is the documented consequence of the design, not a
   silent failure — the audit log records the placeholders that were issued.
7. **Do not stack two redacting gateways.** Masking twice produces placeholders
   that neither side can restore. Run this one in `audit` mode if an upstream
   gateway already masks.
