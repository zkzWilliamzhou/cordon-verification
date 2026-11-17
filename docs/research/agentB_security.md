# Security and Feasibility Analysis for “cordon”

## Executive conclusion
Cordon’s realistic v0.1 boundary is an **offline evidence generator and policy gate**, not a sandbox. Static scanning can produce a stable, reviewable manifest and block obviously dangerous code before execution; it cannot prove that a skill is harmless, detect semantics-free prompt injection, or prevent a process that has already been allowed to execute from escaping. On Linux, Landlock can unprivilegedly restrict ambient filesystem rights, and seccomp-bpf filters can persist across `execve` only after `no_new_privs` is set [1][2]. On macOS, `sandbox-exec` is not a safe v0.1 dependency for new tooling: current Apple guidance emphasizes mandatory access control for sandboxing, while public commentary treats `sandbox-exec` as deprecated [3][4]. AppContainer provides meaningful Windows isolation but is not a pure-Python construct [5]. Therefore a stdlib-only Python wrapper may legitimately claim deterministic scanning, advisory policy warnings, and hash/chain verification; it must **not** claim to have “enforced” runtime isolation unless an external kernel boundary is actually present and fails closed.

## Threat model and mitigation priorities
The highest-impact scenario is a malicious or compromised publisher, not a benign typo. A skill’s `SKILL.md` may contain parser-relevant instructions in YAML frontmatter, HTML comments, Markdown links, reference labels, fenced code, or prose. Base64, concatenated keywords, zero-width joiners, homoglyphs, and bidirectional controls can conceal an instruction or a domain. Unicode bidi formatting characters can alter display order; UAX #9 explicitly notes security issues and deprecates directional overrides where possible [6]. The scanner must preserve a normalized text model, flag invisible/control characters with code-point evidence, decode common text encodings at bounded size, and detect syntax-aware language features rather than matching `curl` in prose. It cannot decide whether a model will obey text; that remains **advisory**.

Destructive shell and execution risk is high likelihood and high impact. “Dangerous” is structural, not lexical: `rm -rf` with a variable, `curl|sh`, `wget -O-|bash`, `eval`/`exec`, `python -c`, `sh -c`, `sudo`, `chmod` to world-writable or setuid modes, and backtick/`$()` substitution should be parsed in shell-context regions. Context matters: `rm -rf "$BUILD_DIR"` inside a job-owned tempdir is different from `rm -rf /`, and quoted documentation is not a shell execution. Use a small shell tokenizer or `shlex` plus targeted grammar, then emit evidence, scope, and confidence. A keyword blacklist invites both false negatives through encoding/trivial renaming and false positives on documentation.

Exfiltration is best represented as a **flow finding**: read of environment variables, SSH/cloud metadata/config, a secret pattern, or a file outside the declared workspace followed by an outbound network sink. Detect candidate URLs, DNS helper calls, HTTP client libraries, `socket`, `/dev/tcp`, and public IP literals; do not claim all exfiltration is detectable. TOCTOU is high impact but only realized at runtime: scan and execution are separate transactions, so a SHA-256 manifest cannot itself close the race. Re-scan atomically immediately before launch, open the directory or files with `O_NOFOLLOW`, compare inodes or hashes after open, and refuse swapped or symlinked targets. `Path.walk()` does not follow symlinks by default, but Python’s own documentation warns that a directory can be replaced by a symlink during the walk, so symlink rejection alone is insufficient [7].

Manifest tampering, chain forgery, and key compromise require separate controls. Sign the canonical manifest with Ed25519; do not use the SHA-256 chain as a signature. The `cryptography` library supports `Ed25519PrivateKey.generate`, 64-byte `sign`, and `verify`; it explicitly labels this a hazardous-materials interface [8]. Store keys in an OS-backed store or an encrypted file with mandatory passphrase/KDF, never inside the scanned skill tree, and separate signing from verification keys. A compromised local user who controls the trusted public key, the writer, or the verification process defeats the design; document that explicitly.

## Cross-platform enforcement reality
| Mechanism | Unprivileged? | v0.1 honest role | Important limit |
|---|---:|---|---|
| Landlock | Yes, self-restrict | Enforce FS path rules | Does not replace seccomp/network policy [1] |
| `seccomp` + `no_new_privs` | Yes, with `no_new_privs` | Reduce syscalls, block network | `no_new_privs` does not block all privilege changes [2] |
| bubblewrap | Usually needs user namespaces or setuid helper | External backend | Not pure-Python and not guaranteed unprivileged |
| macOS `sandbox-exec` | Depends on system/profile | External backend only | Deprecated status makes it unsuitable as a default |
| Windows AppContainer | Requires proper process setup | Strong OS boundary | Not a stdlib-Python primitive [5] |
| Pure Python shim | N/A | Pre-exec policy checks | Bypassable; advisory unless wrapped in a kernel boundary |

A PATH shim is security theatre if the launcher simply checks command names. The child can alter `PATH`, call an absolute interpreter, execute a writable library/config, inherit `LD_PRELOAD`, `PYTHONPATH`, or a wrapper script, or spawn its own child. A PATH check must resolve each executable to a real path, refuse writable/non-root-owned or non-allowlisted binaries, sanitize the environment, and still rely on OS controls to be enforceable. `LD_PRELOAD` and absolute paths are findings; only an OS policy makes denial meaningful.

## Static analysis design and crypto
Findings must be deterministic and reviewable. Use a schema with `finding_id` (rule + normalized location, not line-dependent where possible), `rule_id`, `severity`, `file`, `line`, `column`, `matched_text` redacted or truncated, `context` (doc/shell/python/url), `capability`, and `confidence`. Sort output by ID and file position so reports are diff-stable. The scan should: (1) enumerate only a declared allowlist of file names/extensions, refusing device files, symlinks, hardlink duplicates, and unsupported archive types; (2) read with size, total-size, and archive-member limits to blunt decompression bombs; (3) parse YAML frontmatter with a safe loader and quote the raw bytes separately from interpreted values; (4) parse fenced code by language; (5) run shell/Python taint rules; (6) normalize Unicode NFC/NFKC only for display and preserve original bytes for hashing; (7) cap regex input length; (8) never execute, fetch, or import third-party skill code. ReDoS is prevented by avoiding nested quantifiers over user-controlled alternatives, capping input and match counts, and using `re` only with fixed patterns; Python’s standard library `re` has no regex timeout, so length caps and linear patterns are mandatory [9].

Canonicalization is necessary for reproducibility but is not authentication. RFC 8785 defines a canonical JSON representation for repeatable hashing/signing; it is informational, not a standard [10]. For v0.1, emit UTF-8 canonical JSON with sorted keys, no whitespace, and stable number formatting; reject NaN/Infinity and duplicate object keys. A signed manifest record should contain `manifest_version`, `tool_version`, `created_utc`, sorted `files[]` with path and SHA-256, `capabilities[]`, `policy_hash`, and `scan_findings_digest`; sign that canonical bytes and attach a detached signature plus the verifying key ID, algorithm, and key source. Reject manifests that omit a required field, use an unsupported algorithm, or do not verify under the pinned/trusted key.

The ledger is append-only and hash-evident, not immutable by itself. Each entry should contain `index`, `prev_hash`, canonical event JSON, `entry_hash`, event time, writer ID, event kind, and outcome. `prev_hash` should cover the hash of the prior canonical entry; verify both internal hash and chain linkage. Rotate keys with a signed transition and a superseding key ID; keep the verification key outside the writable ledger directory. Absence of an expected record, clock rollback, ledger truncation, and physical deletion are not detectable from the chain alone. Send a hash to a write-only remote sink or WORM storage for non-repudiation; without that, label the chain “tamper-evident under control of the local writer,” not “append-only.”

## Honest v0.1 scope and acceptance tests
v0.1 must run on Python 3.10 from the standard library plus `cryptography`. Core features: manifest creation/verification, capability allowlist policy, deterministic JSON output, SHA-256 per file and manifest, optional Ed25519 detached signature, canonical chain verification, symlink/inode controls, and a clearly separated **advisory scanner**. Ship these tests: hidden HTML comment and reference-link instructions; base64 that decodes to a network sink; ZWSP/RLI/RLO in code; `rm -rf /`, `rm -rf "$X"` in workspace, and documentation `rm -rf`; `curl|sh`, `bash -c`, `sudo chmod 4777`; DNS/HTTP/exfiltration flows; a symlink escaping the root; a directory replaced by a symlink between check and open; a malicious archive with `../`, absolute paths, symlink members, and oversize ratio; ReDoS inputs; manifest byte substitution; missing, reordered, and forged chain entries; wrong-key and invalid-signature manifests. Each negative test must fail closed, and each benign case must retain its line/context evidence.

Explicitly label the following **advisory / best-effort**: semantic prompt injection detection; non-canonical Unicode/homoglyph identity; obfuscated payloads not decoded by the enabled decoders; complete exfiltration coverage; runtime prevention from a pure-Python wrapper; PATH-shim enforcement; LD_PRELOAD blocking; archive safety beyond declared supported formats; and ledger resistance to deletion or key compromise. “The scanner ran with no critical findings” must never be displayed as “the skill is safe.” Cordon is useful only when it makes the next security decision—manual review, OS-level containment, or deny—explicit and falsifiable.

## References
[1] https://landlock.io/
> “Landlock empowers any process, including unprivileged ones, to securely restrict themselves.”

[2] https://landlock.io/linux-doc/landlock-v34/userspace-api/no_new_privs.html
> “Unprivileged users are therefore only allowed to install such filters if no_new_privs is set.”

[3] https://support.apple.com/guide/security/system-integrity-protection-secb7ea06b49/web
> “macOS utilizes kernel permissions to limit writability of critical system files with a feature called System Integrity Protection.”

[4] https://ones.com.cn/?p=297750
> “Apple 官方已将其标注为 Deprecated（弃用）。”

[5] https://learn.microsoft.com/windows/win32/secauthz/appcontainer-isolation
> “Isolation is AppContainer execution environment’s main objective.”

[6] https://www.unicode.org/L2/L2023/23092-uax-9-47-draft-pri460.pdf
> “directional overrides can be nested one inside another, and in embeddings and isolates.”

[7] https://docs.python.org/3/library/pathlib.html
> “if a directory from dirnames has been replaced with a symlink and follow_symlinks is false, Path.walk() will still try to descend into it.”

[8] https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
> “Returns: The 64 byte signature.”

[9] https://www.owasp.org/index.php?title=Input_Validation_Cheat_Sheet&oldid=118073
> “Constructing a regular expression with unsanitized user input is dangerous.”

[10] https://www.rfc-editor.org/rfc/inline-errata/rfc8785.html
> “This specification defines how to create a canonical representation of JSON data.”
