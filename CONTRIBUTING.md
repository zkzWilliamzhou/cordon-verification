# Contributing

You can add a rule, an adapter, a test or a spec correction. Keep the trust
labels accurate. A pull request that calls an advisory shim "enforced" will be
rejected.

## Setup

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m cordon demo
make check
```

Python 3.10 or newer. `cryptography` is optional; install it to run the
signature tests. No service, account or API key is required.

## Adding a detection rule

1. Add the rule id, severity, capability and message to `RULES` in
   `src/cordon/inspector.py`.
2. Use a fixed regex without nested quantifiers over untrusted alternatives.
   Cap the input line length. Do not add a keyword blacklist.
3. Add a positive fixture and a benign negative fixture. Documentation prose
   must stay non-blocking: findings in prose get medium severity and medium
   confidence.
4. Add a test in `tests/test_cordon.py` that asserts the rule id and the
   location. Run the whole suite.
5. Record the new rule in `docs/spec/CAPABILITY-MANIFEST-v1.md` if it changes
   derived capabilities.

## Adding an adapter

Read `docs/adapters.md`. An adapter calls `cordon hook --manifest ... --stdin`
and forwards the JSON decision. Add a conformance test that feeds the same
three tool calls through every adapter and asserts identical decisions.

## Skills provenance

The 30 vendored skills and five pinned source tarballs must stay consistent
with `docs/skills-lock.json`. Run `make skills-verify` before shipping. Never
hand-edit a skill folder to fix a hash mismatch; rebuild from the pinned
tarballs with `python3 scripts/install_skills.py`, or update the lockfile
deliberately and explain the source change in the pull request. A new source
needs a pinned tarball hash, a licence review and an offline reinstall test.

## Architecture work

Read `GLOSSARY.md` and `docs/adr/`. Use the vocabulary module, interface,
depth, seam, adapter, leverage and locality. Before any refactor, run
`python3 scripts/golden.py --out docs/review/golden_before.json`. After the
refactor, write `golden_after.json` and prove the two files are byte-identical.
Then run `python3 scripts/verify_equivalence.py`. It rebuilds the pre-refactor
modules in a temporary checkout and compares four snapshots, so a rewritten
before-file cannot fake the result. A refactor that changes any output fails
review.

## Review rounds

`python3 scripts/review_harness.py --all` runs nine adversarial rounds. Each
round logs real command output in `docs/review/`. A fix without a regression
test is not a fix.

## Licence

MIT for the CLI and the two formats. Vendored skills keep upstream licences.
