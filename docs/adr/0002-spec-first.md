# ADR-0002: publish two versioned formats

Date: 2026-11-11. Status: accepted.

## Decision

Ship `cordon.capability-manifest/v1` and `cordon.ledger/v1` as plain JSON with
frozen schemas, canonical hashing rules and conformance examples. Other
harnesses can implement either format without installing Cordon.

## Reason

Agent C found that portability and a published format lower coordination cost.
A format also survives a vendor shipping a competing CLI. The integration
stays valuable even if a large project adopts the contract.

## Consequences

`docs/spec/` holds the normative text. Any field removal or hash-input change
needs a new schema string. Adapters in `docs/adapters.md` read the shared
manifest, so one decision matches across harnesses.
