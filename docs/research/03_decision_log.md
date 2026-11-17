# Decision log (pre-registered criteria, raw scores, dissent)

Date: 2026-11-11. Decision owner: manager. Evidence status after Agent A/B/C: `search-incomplete` (bounded web search, 2026-11-11), `support-located` for the narrow five-part novelty claim, `challenge-located` for the stronger claim "no similar tool exists".

Shortlist after clustering: I01 (integrated trust boundary), I02 (flight recorder), I10 (SBOM/registry), I11 (reverse-engineer-any-app MCP). I02 and I10 were merged into I01 as components. I11 was vetoed.

Scores are ranges 1–10 with uncertainty, weights from `00_session_scope.md`. Weighted score uses the midpoint; sensitivity was checked by moving each weight +0.10 in turn (ranking never changed).

| Idea | C1 .20 | C2 .20 | C3 .15 | C4 .10 | C5 .15 | C6 .10 | C7 .10 | Midpoint | Veto | Outcome |
|---|---|---|---|---|---|---|---|---|---|---|
| I01 Cordon | 7–9 | 8–9 | 9–10 | 8–9 | 8–9 | 9–10 | 9 | **8.5** | none | **chosen, with reduced enforcement claim** |
| I02 Flight recorder | 4–6 | 6–7 | 8 | 6 | 6 | 8 | 8 | 6.4 | none | merged as ledger component |
| I10 SBOM + registry | 3–5 | 5–6 | 5 | 4 | 8 | 9 | 7 | 5.6 | V4 (needs network governance) | merged as pin/sign component |
| I11 Reverse-engineer MCP | 1 | 8 | 2 | 8 | 7 | 7 | 6 | 4.7 | **V1 exact collision** | rejected |
| I12 Slop ledger | 2–4 | 5 | 9 | 7 | 5 | 9 | 9 | 5.8 | V1 (StopSlop exists) | rejected |

**Why I01 won.** It is the only shortlisted idea where the integration itself changes a decision the user can make today: install, deny, contain, or audit. It scores 10 on buildability because the whole chain runs offline on Python 3.10, and 9 on integrity because it is defensive and does not require running untrusted code.

**Dissent preserved.** P06: security tools rarely spread because adoption is a chore; a format spreads faster than a tool. Response: we ship both, format first in the spec directory, tool first in the README. P05: a non-expert must understand it in one sentence. Response: the README first line is "Cordon tells you what an AI skill is allowed to touch, then checks every tool call against that list." P08: root-required enforcement excludes most users. Response: no root requirement; OS backends are optional upgrades. P02: a scanner alone is a commodity. Response: acceptance test AT-07 binds scan to manifest to hook to ledger.

**Veto outcomes.** V1 triggered for I11 and I12. V2/V3/V4 clear for I01. No veto was hidden inside an average.

**Gate outcomes.** Human-subjects, clinical, biosafety and export-control gates: not implicated. Data governance: the tool reads local files only, never uploads. Dual-use: the scanner is defensive; publishing detection rules also tells an attacker what is detected, which is accepted and documented in `SECURITY.md`.

**Decision.** Build Cordon v0.1. Next action: implementation plan, then execution, then nine review rounds, then architecture deepening with a byte-for-byte behaviour-equivalence gate.

**Revisit triggers.** (1) A maintained tool is found that binds all five capabilities. (2) AT-07 fails. (3) False-positive rate on the bundled benign corpus exceeds the documented threshold. (4) A reviewer finds a bypass we described as enforced rather than advisory.

**What we did not achieve.** We did not publish to GitHub, did not obtain 105k stars, did not get human approval of the design, and did not prove non-existence. Any claim otherwise would be false.
