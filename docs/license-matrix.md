# License Matrix

## Project policy

- Default project licensing target: dual `MIT OR Apache-2.0`.
- Prefer dependencies under MIT / Apache-2.0 / BSD.
- GPL-family dependencies are disallowed in this phase.
- LGPL dependencies require explicit isolation and compliance review.

## Dependency categories

| Category | Allowed | Review required | Disallowed |
|---|---|---|---|
| Permissive | MIT, Apache-2.0, BSD-2/3-Clause, ISC | No | No |
| Weak copyleft | MPL-2.0 | Yes | No |
| LGPL | LGPL-2.1/3.0 | Yes (dynamic-link + notices) | No |
| Strong copyleft | GPL-2.0/3.0, AGPL | No | Yes |
| Proprietary redistributables | Vendor-specific | Yes | Depends |

## Initial dependency decisions

- .NET packages:
  - `Microsoft.Data.Sqlite` (MIT)
  - `System.Management` (MIT)
- Rust workspace baseline:
  - `serde`, `serde_json`, `thiserror`, `chrono` (permissive)

## Compliance implementation

- Machine-readable inventory: `tools/dependency-licenses.json`.
- CI gate: `scripts/license-gate.ps1 -Check` (wired into `.github/workflows/ci.yml`).
- Third-party notices file: `docs/third-party-notices.md` (generated from inventory).

## Clean-room notes

- No direct code reuse from TestDisk/PhotoRec/winfr.
- Recovery design is implemented from specification and publicly documented filesystem behavior.
