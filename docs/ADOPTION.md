# Adoption, honestly

The user asked for a program that can get over 105,000 GitHub stars. Stars come
from other people. This project cannot guarantee, buy or manufacture them. It
also did not publish a repository in this run. `docs/research/agentC_adoption.md`
holds the full skeptical report.

## What the evidence says

A 100k-star repository is a rare cultural event, not a routine engineering
milestone. GitHub does not publish a public star distribution. A third-party
dataset in the report claims 132 repositories above 100k out of 32.6 million
starred repositories as of 2026-10-18; the report marks that figure unverified
because the snapshot was not independently reproduced. Do not quote it as a
benchmark.

Four 2023-2026 cases show distinct mechanisms: AutoGPT rode the GPT-4 moment
with a 30-second autonomous demo; OpenClaw combined local execution with
multi-platform reach; Anthropic published Agent Skills as a portable open
standard; the OpenAI Agents SDK lowered orchestration cost with a small SDK.
Each reduced coordination cost. None won by adding a chore.

Security tools face a structural penalty. Alerts without context, false
positives and merge friction erode trust. Cordon therefore defaults to
changed-artifact scanning, blocks only high-confidence findings, prints a
stable finding id with a location, and gives a one-command demo.

We measured the noise ourselves. Round 8 scanned the 30 vendored skills: 141
files, 371 findings, 71 blocking under `--fail-on high`. Most came from URLs and
`subprocess` examples inside fenced code in legitimate skills. A structural
indicator scanner cannot tell an example from an instruction. The fix shipped
in v0.1 is a reviewed baseline (`--write-baseline` / `--baseline`): accept the
reviewed corpus once, then gate only finding ids that are new. The report keeps
showing every finding. See `docs/review/round08.md` for the command and output.
A public false-positive rate on a labelled corpus remains v0.2 work. Publishing
371 findings as 371 vulnerabilities would be dishonest.

## Conditions that would help

- One copy-paste install command on Linux, macOS and Windows, tested in CI.
- A 30-second demo with a visible verdict and no setup.
- A frozen, royalty-free format others can implement. See `docs/spec/`.
- Tested adapters with a public conformance matrix, not a logo count.
- A GitHub Action that comments only on changed skills and uploads SARIF.
- A public corpus with disclosed false-positive and false-negative rates.
- Fast fixes for critical bugs, a clear security policy, and good first issues.

## Pre-mortem: eight ways this fails

| Failure | Early warning |
|---|---|
| Nobody can install it | New-user issues outnumber successful installs |
| Demo impresses but CI never adopts | High README views, near-zero Action deployments |
| Noisy scanner | Most findings dismissed without remediation in week one |
| Sandbox overclaim causes a breach | Users cite the shim as a reason to disable other controls |
| Ecosystem lock-in | Adapters exist for one vendor only |
| Format unstable | Incompatible third-party readers within one minor version |
| Maintenance breaks trust | Critical bugs stay open while cosmetic releases ship |
| Problem not urgent | Developers route around the tool; the queue fills with config questions |

## What we refuse

No star buying, no fabricated growth numbers, no "100% safe", no claim that a
shim enforces anything, no launch of twenty adapters with zero conformance
tests. If the tool cannot show fewer missed detections and fewer false blocks
than the status quo, kill it as a popularity play even if the code works.
