# Adapters

Every adapter reads the same `cordon.json`. One policy decision therefore
matches across harnesses. Cover four adapters with conformance tests before
you claim interoperability.

## Claude Code PreToolUse hook

Add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{
        "type": "command",
        "command": "cordon hook --manifest ./cordon.json --ledger ./.cordon/audit.jsonl --stdin"
      }]
    }]
  }
}
```

Cordon reads the tool-call JSON on stdin and prints
`hookSpecificOutput.permissionDecision` with `allow` or `deny`. A deny blocks
the call inside Claude Code. It does not stop a process the harness already
launched. Keep the manifest and ledger outside any skill folder.

## Generic JSON hook

```bash
cordon hook --manifest cordon.json --agent generic --stdin \
  --exit-on-deny < tool-call.json
```

Output: `{"decision": ..., "reason": ..., "capability": ..., "detail": ...}`.
Exit code 126 signals a deny to a CI gate. Adapt this shape for Codex, Cursor,
Gemini CLI and OpenCode by mapping their tool names into
`tool_name`/`tool_input`. The engine fails closed on unknown tools.

## GitHub Actions

```yaml
- uses: actions/setup-python@v5
  with: {python-version: '3.10'}
- run: pipx install .
- run: cordon scan ./skills --format sarif --out cordon.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: cordon.sarif}
```

`--fail-on high` blocks only high-confidence critical and high findings.
Documentation prose produces medium findings, so it does not block a merge.
A workflow example lives in `.github/workflows/ci.yml`.

For a repository that already vendors many third-party skills, commit a
reviewed baseline and gate only new finding ids:

```yaml
- run: cordon scan ./skills --format sarif --out cordon.sarif \
        --fail-on high --baseline .cordon/accepted.json
```

Create the baseline once with `--write-baseline .cordon/accepted.json` after a
human reads every finding. The SARIF file still lists all findings.

## pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: cordon
        name: cordon skill scan
        entry: cordon scan --fail-on high
        language: system
        files: 'SKILL\.md$|\.agents/skills/'
        pass_filenames: false
```

## Advisory guard

```bash
cordon guard --manifest cordon.json --pin cordon-pin.json \
  --ledger audit.jsonl -- ./agent-cli --task "tidy json"
```

`guard` re-verifies the pin, generates shims for executable basenames on the
original PATH, strips a fixed list of dangerous environment variables, and logs
each intercepted call. It prints an advisory notice before launch. Known
bypasses are in `SECURITY.md`.

## OS backend upgrade (not shipped)

Wrap the guarded command in Landlock on Linux, bubblewrap where user namespaces
exist, or an AppContainer on Windows. Keep the manifest as the policy source.
Only then set `policy.mode` to `enforced`, and only with conformance tests that
prove a bypass attempt fails closed. See ADR-0001.
