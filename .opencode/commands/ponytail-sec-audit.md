---
description: Run Ponytail Sec security audit (writes restricted to .ponytail-sec/**)
agent: ponytail-sec-audit
subtask: true
---

Perform a Ponytail Sec security audit on `$ARGUMENTS` and write schema v3 output to `.ponytail-sec/` with all secret values redacted.
