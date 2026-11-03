# ponytail-sec-opencode (OpenCode V2 Hardened Edition)

Dedicated OpenCode V2 fork of [andypitcher/ponytail-sec](https://github.com/andypitcher/ponytail-sec) (pinned base commit `78c6c1a4665320889144db77854e65fc214eed96`).

## Security, Privacy & OpenCode V2 Enhancements

1. **Native OpenCode V2 Commands & Least-Privilege Subagents**:
   - Converted upstream `commands/*.toml` to OpenCode native Markdown commands (`.opencode/commands/ponytail-sec{,-audit,-triage}.md`).
   - Hardened `.opencode/agents/ponytail-sec-triage.md` (strictly read-only: `deny` on `edit`, `shell`, `webfetch`, `websearch`, `subagent`, `external_directory`, and local secret/key files `*.env`, `*.pem`, `*.key`, `*id_rsa*`) and `.opencode/agents/ponytail-sec-audit.md` (`edit` allowed only inside `.ponytail-sec/*`).

2. **5 Triage Bash Scripts Hardened (Fixes 6 Upstream Linux & Validation Defects)**:
   - **Debian/Ubuntu `jq 1.6` Compatibility (`check-triage.sh`)**: Renamed reserved keyword `as $end` to `as $end_idx`, fixing `jq: error: syntax error, unexpected end` (`exit 3`) on Debian Bookworm / Ubuntu 22.04.
   - **Large Evidence File Support (`150 KB` / `1 MB`)**: Replaced `jq --argjson evidence_files "$evidence_files"` with temp-file `--slurpfile evidence_files_arr`, eliminating Linux `MAX_ARG_STRLEN` (`128 KB`) `/usr/bin/jq: Argument list too long (exit 126)`.
   - **FIRST.org CVSS v4.0 Mathematical Score Congruence (`cvss4-calc.mjs`)**: Validates all 11 mandatory CVSS 4.0 base metrics and verifies that the computed score matches `cvss_score` within `±0.1`.
   - **Strict `findings_sha256` Integrity Enforcement (`find-scan.sh`)**: Exits `1` (instead of printing a warning and exiting `0`) when `findings.json` does not match `meta.json`.
   - **Unmasked Secret Blocking (`check-triage.sh`)**: Rejects triage reports and evidence files containing unredacted secret patterns (`sk_live_`, `AKIA...`, `ghp_...`, private keys, JWT/Bearer tokens) or symlinks.
   - **File Permissions & Git Ignore (`umask 077`)**: Enforces `0600`/`0700` permissions and automatically creates `.ponytail-sec/.gitignore` with `*`.
