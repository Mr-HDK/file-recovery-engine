# Expansion Phase Runbook (Codex Execution Contract)

## Purpose

This runbook defines how the `Codex agent` must execute each roadmap phase from start to completion.

## One-phase execution lifecycle

### 1. Phase kickoff

- Confirm current phase number and scope from `docs/expansion-program-roadmap.md`.
- Create a phase branch named `codex/phase-<number>-<short-topic>`.
- Publish phase implementation plan in a markdown artifact under `docs/phases/`.

### 2. Design and interfaces

- Define crate/module boundaries before coding.
- Define/extend FFI contracts and status-code mappings.
- Define data model additions in UI/core persistence.
- Confirm backward compatibility for existing sessions.

### 3. Implementation

- Implement engine crate changes first.
- Implement FFI bridge next.
- Implement .NET probe/UI integration next.
- Keep safety checks and destination-separation logic intact.

### 4. Test and validation

- Add unit tests for parser/core logic.
- Add FFI integration tests for candidate mapping and recovery behaviors.
- Add UI/core tests for persistence and status mapping.
- Add host or image fixture validation script updates when relevant.

### 5. Documentation and operator readiness

- Update affected docs in `docs/`.
- Add/refresh test fixtures and manifests.
- Record known limitations explicitly.
- Update operational scripts if phase adds new runtime paths.

### 6. Phase completion gate

- All required tests pass.
- No critical safety regressions.
- Phase checklist marked complete in `docs/expansion-phase-tracker.md`.
- Next phase is not started until this gate is satisfied.

## Mandatory deliverables for every phase

- Code changes across engine, FFI, and UI where applicable.
- Tests proving new functionality and non-regression.
- Updated docs for architecture, pipeline, and test plan sections touched.
- Clear status mapping for new failure modes.
- Recovery diagnostics for partial/unsupported outcomes.

## Prohibited shortcuts

- No skipping tests for parser/FFI boundary changes.
- No direct write paths to source media.
- No silent fallback for unsupported formats or decode failures.
- No phase overlap that hides incomplete acceptance criteria.

## Required phase artifact files

For each phase `N`, create:

- `docs/phases/phase-N-plan.md`
- `docs/phases/phase-N-validation.md`
- `docs/phases/phase-N-retrospective.md`

Each file must include date, owner (`Codex agent`), scope, completed work, test evidence, and open risks.

