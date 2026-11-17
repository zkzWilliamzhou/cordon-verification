# ADR-0005: architecture refactors must prove byte-identical behaviour

Date: 2026-11-11. Status: accepted. Amended 2026-11-12 with an independent proof.

## Decision

Before any architecture deepening, `scripts/golden.py` writes
`docs/review/golden_before.json`. After the refactor it writes
`golden_after.json`. The two files must be byte-identical. A diff fails review
and sends the refactor back.

A stored before-snapshot alone is weak evidence because someone can rewrite it
after the fact. The manager rejected a post-hoc normalisation of the before
file and required an independent reconstruction of the pre-refactor code.
Round 9 must invoke `scripts/verify_equivalence.py` and pass.

## Reason

The user required that the architecture pass change no function of the
program. Prose claims of equivalence are not evidence. The snapshot covers CLI
stdout, exit codes, scan digests, finding ids, report hashes, derived
capabilities, hook decisions, ledger verification, signed-pin digests and the
guard dry run.

## Consequences

`scripts/golden.py` uses relative fixture paths, so a snapshot never depends on
the checkout directory. `scripts/legacy_reconstruction.py` rebuilds the exact
pre-refactor modules in a temporary checkout. `scripts/verify_equivalence.py`
runs the same golden tool on both versions and requires four byte-identical
comparisons: recorded before, recorded after, freshly rebuilt legacy, and the
current final code.

`docs/review/round09.md`, `equivalence-proof.txt` and `harness_final.txt` store
the real output. Any future refactor repeats the whole gate. A failure sends the
specific module back to the implementer; a fix without a regression test is not
a fix.
