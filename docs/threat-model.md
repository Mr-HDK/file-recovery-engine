# Threat Model

## Assets

- User source media and remaining intact data.
- Recovered output data.
- Session metadata/logs containing path and filename information.

## Adversarial/accidental threats

1. Accidental overwrite of source volume.
- Mitigation: strict source/destination separation gate.

2. Misleading confidence or status reporting.
- Mitigation: evidence-backed confidence model and status taxonomy.

3. Privilege misuse.
- Mitigation: least-privilege operation where possible and elevation warnings.

4. Corrupted parser input causing crashes.
- Mitigation: parser fuzzing and defensive bounds checking.

5. Sensitive metadata leakage via logs.
- Mitigation: scoped logs and operator-visible log locations.

6. Supply-chain risk from incompatible dependencies.
- Mitigation: license matrix and machine-readable inventory.

## Trust boundaries

- UI process boundary.
- Rust FFI boundary.
- OS device I/O boundary.
- Persisted local SQLite/log storage boundary.

## Current residual risks

- Raw device read-only enforcement is not yet implemented in Rust runtime code.
- Engine-side parser hardening is scaffolded but not complete.
- UI currently trusts local machine context and does not yet sandbox plugins/extensions.

Residual risks are tracked in `docs/todo-risk-register.md`.
