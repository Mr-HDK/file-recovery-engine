# Signature Pack Compatibility Matrix

## Pack
- Name: `core-signatures`
- Version: `2026.04-r3`
- Target coverage: `250+` identifiers

## Families
| Family | Toggle | Notes |
|---|---|---|
| `images` | `CarveFamilyImages` | Core raster/photo formats + modern image containers. |
| `documents` | `CarveFamilyDocuments` | Text, office-adjacent and structured document identifiers. |
| `archives` | `CarveFamilyArchives` | ZIP/7z/RAR/tar-like identifiers. |
| `office` | `CarveFamilyOffice` | Office container-specific identifiers. |
| `media` | `CarveFamilyMedia` | Audio/video identifiers. |
| `artifacts` | `CarveFamilyArtifacts` | Secondary evidence artifacts (thumbcache, caches). |

## Compatibility Rules
1. Pack metadata is surfaced through `fr_get_carve_signature_pack_metadata`.
2. UI and reports record `pack@version` and selected family toggles in session artifacts.
3. Older sessions remain readable; missing pack metadata is treated as `pack=core-signatures@unknown`.
4. Secondary artifact families remain opt-in to avoid noisy default scans.

## Upgrade Notes
1. `2026.04-r3` expands metadata coverage to `>=250` identifiers and preserves existing core validated carve logic.
2. Existing FFI metadata buffer for `formats_csv` is expanded to support long catalogs.
3. Consumers should not assume fixed small CSV payload sizes when reading signature metadata.
