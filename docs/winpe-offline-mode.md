# WinPE Offline Recovery Mode

## Purpose

This document describes how to build and run the Windows app in a bootable WinPE environment for offline recovery workflows.

## Prerequisites

- Windows ADK installed.
- WinPE add-on installed.
- Elevated PowerShell session.
- Repository checked out locally.

## Build WinPE media

Use the Phase 16 packaging script:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/winpe/build-winpe-media.ps1 `
  -Architecture amd64 `
  -WorkDirectory artifacts/winpe `
  -OutputIsoPath artifacts/winpe/file-recovery-winpe.iso
```

Optional USB creation:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/winpe/build-winpe-media.ps1 `
  -Architecture amd64 `
  -WorkDirectory artifacts/winpe `
  -OutputIsoPath artifacts/winpe/file-recovery-winpe.iso `
  -UsbDriveLetter E
```

## Offline startup behavior

- The WinPE startup script sets `FR_WINPE_MODE=1`.
- The app is launched from `X:\RecoveryApp\FileRecovery.WindowsApp.exe`.
- Startup events are logged to `X:\file-recovery-winpe-startup.log`.

## Runtime validation in app

When running in WinPE mode, the app reports:

- Runtime mode indicator (`WinPE Offline`).
- Offline readiness diagnostics:
- critical driver presence checks (`disk.sys`, `partmgr.sys`, `storport.sys`).
- visible source count.
- visible destination volume count.

WinPE mode guardrails currently include:

- VSS snapshot enumeration disabled.
- network source intake disabled.

## Verification checklist

- Boot VM or hardware from generated ISO/USB.
- Confirm app launches automatically.
- Confirm runtime mode shows `WinPE Offline`.
- Confirm at least one source and one destination volume are visible.
- Run a quick scan session and export candidate list.
