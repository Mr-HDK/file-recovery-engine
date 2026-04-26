using FileRecovery.WindowsApp.Core.Models;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace FileRecovery.WindowsApp.Core.Engine;

public sealed record EngineSourceProbeResult(
    bool EngineAvailable,
    bool OpenedReadOnly,
    ulong SizeBytes,
    string Message,
    int StatusCode
);

public sealed record EngineSessionOpenResult(
    bool EngineAvailable,
    bool Opened,
    ulong SessionId,
    ulong SizeBytes,
    uint AlignmentBytes,
    string Message,
    int StatusCode
);

public sealed record EngineChunkReadResult(
    bool EngineAvailable,
    bool Success,
    uint BytesRead,
    string Message,
    int StatusCode
);

public sealed record EngineNtfsBootMetadata(
    ushort BytesPerSector,
    byte SectorsPerCluster,
    uint ClusterSizeBytes,
    uint FileRecordSizeBytes,
    uint IndexRecordSizeBytes,
    ulong MftCluster,
    ulong MftOffsetBytes,
    ulong VolumeSizeBytes,
    ulong VolumeSerial
);

public sealed record EngineNtfsBootProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineNtfsBootMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineRefsBootMetadata(
    ushort BytesPerSector,
    byte SectorsPerCluster,
    uint ClusterSizeBytes,
    ulong TotalSectors,
    ulong VolumeSizeBytes,
    ulong VolumeSerial
);

public sealed record EngineRefsBootProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineRefsBootMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineRefsDeletedCandidate(
    bool Deleted,
    ulong ObjectId,
    ulong SizeBytes,
    string? Name,
    string? ReconstructedPath
);

public sealed record EngineRefsDeletedCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineRefsDeletedCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineExtSuperblockMetadata(
    string Filesystem,
    uint BlockSizeBytes,
    ushort InodeSizeBytes,
    uint InodesPerGroup,
    uint TotalInodes,
    ulong TotalBlocks
);

public sealed record EngineExtSuperblockProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineExtSuperblockMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineExtDeletedCandidate(
    bool Deleted,
    bool IsDirectory,
    ulong InodeNumber,
    ulong EntryOffsetBytes,
    ulong SizeBytes,
    string? Name,
    string? ReconstructedPath
);

public sealed record EngineExtDeletedCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineExtDeletedCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineXfsSuperblockMetadata(
    uint BlockSizeBytes,
    ushort InodeSizeBytes,
    uint AllocationGroupCount,
    ulong DataBlocks
);

public sealed record EngineXfsSuperblockProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineXfsSuperblockMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineXfsDeletedCandidate(
    bool Deleted,
    bool IsDirectory,
    ulong InodeNumber,
    ulong SizeBytes,
    string? Name,
    string? ReconstructedPath
);

public sealed record EngineXfsDeletedCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineXfsDeletedCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineUfsSuperblockMetadata(
    uint Magic,
    uint BlockSizeBytes,
    uint FragmentSizeBytes,
    ulong TotalBlocks
);

public sealed record EngineUfsSuperblockProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineUfsSuperblockMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineUfsDeletedCandidate(
    bool Deleted,
    bool IsDirectory,
    uint InodeNumber,
    ulong SizeBytes,
    string? Name,
    string? ReconstructedPath
);

public sealed record EngineUfsDeletedCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineUfsDeletedCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineApfsContainerMetadata(
    uint BlockSizeBytes,
    ulong BlockCount,
    ulong Features,
    ulong IncompatFeatures,
    ulong ContainerObjectId
);

public sealed record EngineApfsContainerProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineApfsContainerMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineApfsDeletedCandidate(
    bool Deleted,
    bool IsDirectory,
    ulong Cnid,
    ulong SizeBytes,
    string? Name,
    string? ReconstructedPath
);

public sealed record EngineApfsDeletedCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineApfsDeletedCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineHfsVolumeMetadata(
    ushort Signature,
    ushort Version,
    uint BlockSizeBytes,
    uint TotalBlocks,
    uint FileCount,
    uint FolderCount
);

public sealed record EngineHfsVolumeProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineHfsVolumeMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineHfsDeletedCandidate(
    bool Deleted,
    bool IsDirectory,
    uint Cnid,
    ulong SizeBytes,
    string? Name,
    string? ReconstructedPath
);

public sealed record EngineHfsDeletedCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineHfsDeletedCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineFatBootMetadata(
    string Filesystem,
    ushort BytesPerSector,
    byte SectorsPerCluster,
    byte FatCount,
    uint ClusterSizeBytes,
    ulong TotalSectors,
    uint RootDirectoryFirstCluster,
    ulong FatOffsetBytes,
    ulong DataRegionOffsetBytes,
    uint VolumeSerial
);

public sealed record EngineFatBootProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineFatBootMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineRaidLayoutMetadata(
    string MetadataFamily,
    string Level,
    uint MemberCount,
    uint StripeSizeBytes,
    ulong DataOffsetBytes,
    string ParityRotation,
    byte ConfidenceScore,
    IReadOnlyList<uint> DiskOrder
);

public sealed record EngineRaidLayoutProbeResult(
    bool EngineAvailable,
    bool Success,
    EngineRaidLayoutMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineVirtualRaidSessionOpenResult(
    bool EngineAvailable,
    bool Success,
    ulong SessionId,
    ulong SizeBytes,
    EngineRaidLayoutMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineRaidManualOverride(
    bool OverrideLevel,
    string? Level,
    bool OverrideStripeSize,
    uint StripeSizeBytes,
    bool OverrideDataOffset,
    ulong DataOffsetBytes,
    bool OverrideParityRotation,
    string? ParityRotation,
    IReadOnlyList<uint>? DiskOrder
);

public sealed record EngineRaidLogicalMapping(
    uint MemberIndex,
    ulong MemberOffsetBytes,
    uint? ParityMemberIndex
);

public sealed record EngineRaidLogicalMappingResult(
    bool EngineAvailable,
    bool Success,
    EngineRaidLogicalMapping? Mapping,
    string Message,
    int StatusCode
);

public sealed record EngineRaidDegradedAssessment(
    uint MissingMemberCount,
    uint SampleCount,
    uint RecoverableSampleCount,
    byte RecoverabilityPercent,
    byte ConfidencePenalty,
    string Recommendation
);

public sealed record EngineRaidDegradedAssessmentResult(
    bool EngineAvailable,
    bool Success,
    EngineRaidDegradedAssessment? Assessment,
    string Message,
    int StatusCode
);

public sealed record EngineNtfsQuickScanResult(
    bool EngineAvailable,
    bool Success,
    uint ParsedRecords,
    uint ParseFailures,
    uint ResidentAttributeCount,
    uint NonResidentAttributeCount,
    uint DeletedRecords,
    uint DirectoryRecords,
    uint NamedRecords,
    uint RecordsWithNonResidentData,
    uint UsnEnrichedRecords,
    uint UsnGhostRecords,
    string Message,
    int StatusCode
);

public sealed record EngineNtfsQuickScanCandidate(
    uint RecordNumber,
    bool InUse,
    bool Deleted,
    bool IsGhostRecord,
    bool IsDirectory,
    bool HasNonResidentData,
    bool HasNamedDataStreams,
    bool IsCompressed,
    bool IsSparse,
    bool IsEncrypted,
    ulong? ParentRecordNumber,
    string? Name,
    string? ReconstructedPath,
    ulong? DataSizeBytes,
    ulong? AllocatedSizeBytes,
    uint? FileAttributes,
    ulong? CreatedFileTimeUtc,
    ulong? ModifiedFileTimeUtc,
    ulong? MftModifiedFileTimeUtc,
    ulong? AccessedFileTimeUtc,
    string EvidenceSources,
    string ConfidenceTier,
    string ConfidenceReason
);

public sealed record EngineNtfsQuickScanCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineNtfsQuickScanCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineFatDeletedCandidate(
    bool Deleted,
    bool IsDirectory,
    uint StartCluster,
    ulong SizeBytes,
    string? Name,
    string? ReconstructedPath
);

public sealed record EngineFatDeletedCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineFatDeletedCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineCarveCandidate(
    ulong OffsetBytes,
    ulong LengthBytes,
    bool Partial,
    string Format,
    string SuggestedName,
    string ConfidenceTier,
    string ConfidenceReason
);

public sealed record EngineCarveCandidatesResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineCarveCandidate> Candidates,
    string Message,
    int StatusCode
);

public sealed record EngineCarveSignaturePackMetadata(
    string PackName,
    string PackVersion,
    uint FormatCount,
    uint FamilyFlags,
    string FormatsCsv
);

public sealed record EngineCarveSignaturePackMetadataResult(
    bool EngineAvailable,
    bool Success,
    EngineCarveSignaturePackMetadata? Metadata,
    string Message,
    int StatusCode
);

public sealed record EngineVssSnapshot(
    string SnapshotId,
    string? VolumeName,
    string DeviceObject,
    string? InstallTimeUtc,
    string SnapshotPath
);

public sealed record EngineVssSnapshotListResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineVssSnapshot> Snapshots,
    string Message,
    int StatusCode
);

public sealed record EngineRecoverCandidateResult(
    bool EngineAvailable,
    bool Success,
    bool Partial,
    ulong BytesWritten,
    uint DiagnosticsFlags,
    string DiagnosticsSummary,
    string Message,
    int StatusCode
);

public sealed record EngineEncryptedSource(
    string Provider,
    string Identifier,
    string DisplayName,
    bool Locked,
    bool SupportsPassword,
    bool SupportsRecoveryKey,
    bool SupportsKeyFile
);

public sealed record EngineEncryptedSourceListResult(
    bool EngineAvailable,
    bool Success,
    IReadOnlyList<EngineEncryptedSource> Sources,
    string Message,
    int StatusCode
);

public sealed record EngineEncryptedSourceUnlockResult(
    bool EngineAvailable,
    bool Success,
    bool Unlocked,
    string Provider,
    string Message,
    int StatusCode
);

public sealed record EngineEncryptedSourceLockResult(
    bool EngineAvailable,
    bool Success,
    bool Locked,
    string Provider,
    string Message,
    int StatusCode
);

public static class NativeEngineProbe
{
    public const uint CarveFamilyImages = 0x0001;
    public const uint CarveFamilyDocuments = 0x0002;
    public const uint CarveFamilyArchives = 0x0004;
    public const uint CarveFamilyOffice = 0x0008;
    public const uint CarveFamilyMedia = 0x0010;
    public const uint CarveFamilyArtifacts = 0x0020;

    public static string GetVersionDisplay()
    {
        try
        {
            var pointer = fr_engine_version();
            if (pointer == IntPtr.Zero)
            {
                return "Engine unavailable";
            }

            return Marshal.PtrToStringUTF8(pointer) ?? "Engine unavailable";
        }
        catch (DllNotFoundException)
        {
            return "Engine unavailable";
        }
        catch (EntryPointNotFoundException)
        {
            return "Engine ABI mismatch";
        }
    }

    public static EngineCarveSignaturePackMetadataResult GetCarveSignaturePackMetadata()
    {
        try
        {
            var native = new NativeCarveSignaturePackMetadata
            {
                PackName = new byte[64],
                PackVersion = new byte[32],
                FormatsCsv = new byte[4096]
            };

            var status = fr_get_carve_signature_pack_metadata(out native);
            if (status != 0)
            {
                return new EngineCarveSignaturePackMetadataResult(
                    true,
                    false,
                    null,
                    "Failed to load carve signature pack metadata.",
                    status);
            }

            var metadata = new EngineCarveSignaturePackMetadata(
                PackName: DecodeUtf8(native.PackName) ?? "core-signatures",
                PackVersion: DecodeUtf8(native.PackVersion) ?? "unknown",
                FormatCount: native.FormatCount,
                FamilyFlags: native.FamilyFlags,
                FormatsCsv: DecodeUtf8(native.FormatsCsv) ?? string.Empty);

            return new EngineCarveSignaturePackMetadataResult(
                true,
                true,
                metadata,
                "Carve signature pack metadata loaded.",
                0);
        }
        catch (DllNotFoundException)
        {
            return new EngineCarveSignaturePackMetadataResult(
                false,
                false,
                null,
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineCarveSignaturePackMetadataResult(
                false,
                false,
                null,
                "Engine ABI mismatch",
                -101);
        }
    }

    public static bool IsHealthy()
    {
        try
        {
            return fr_health_check() == 0;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    public static EngineSourceProbeResult ProbeSourceReadOnly(string sourcePath, RecoverySourceKind sourceKind)
    {
        try
        {
            var normalizedKind = NormalizeSourceKindForEngine(sourceKind);
            var status = fr_probe_source_readonly(sourcePath, (int)normalizedKind, out var sizeBytes);
            return status switch
            {
                0 => new EngineSourceProbeResult(true, true, sizeBytes, "Source opened in read-only mode.", status),
                10 => new EngineSourceProbeResult(true, false, 0, "Engine rejected source path format.", status),
                11 => new EngineSourceProbeResult(true, false, 0, "Engine platform support unavailable.", status),
                12 => new EngineSourceProbeResult(true, false, 0, "Access denied opening source read-only.", status),
                13 => new EngineSourceProbeResult(true, false, 0, "Source not found.", status),
                14 => new EngineSourceProbeResult(true, false, 0, "Windows I/O error while opening source.", status),
                15 => new EngineSourceProbeResult(true, false, 0, "Invalid read offset.", status),
                16 => new EngineSourceProbeResult(true, false, 0, "Misaligned read parameters.", status),
                _ => new EngineSourceProbeResult(true, false, 0, "Unknown engine response.", status),
            };
        }
        catch (DllNotFoundException)
        {
            return new EngineSourceProbeResult(false, false, 0, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineSourceProbeResult(false, false, 0, "Engine ABI mismatch", -101);
        }
    }

    public static EngineSessionOpenResult OpenSourceReadOnlySession(string sourcePath, RecoverySourceKind sourceKind)
    {
        try
        {
            var normalizedKind = NormalizeSourceKindForEngine(sourceKind);
            var status = fr_open_source_session_readonly(sourcePath, (int)normalizedKind, out var sessionId, out var sizeBytes);
            return status switch
            {
                0 => new EngineSessionOpenResult(
                    true,
                    true,
                    sessionId,
                    sizeBytes,
                    TryGetSourceSessionAlignment(sessionId),
                    "Read-only source session opened.",
                    status),
                10 => new EngineSessionOpenResult(true, false, 0, 0, 0, "Engine rejected source path format.", status),
                11 => new EngineSessionOpenResult(true, false, 0, 0, 0, "Engine platform support unavailable.", status),
                12 => new EngineSessionOpenResult(true, false, 0, 0, 0, "Access denied opening source read-only.", status),
                13 => new EngineSessionOpenResult(true, false, 0, 0, 0, "Source not found.", status),
                14 => new EngineSessionOpenResult(true, false, 0, 0, 0, "Windows I/O error while opening source.", status),
                15 => new EngineSessionOpenResult(true, false, 0, 0, 0, "Invalid read offset.", status),
                16 => new EngineSessionOpenResult(true, false, 0, 0, 0, "Misaligned read parameters.", status),
                _ => new EngineSessionOpenResult(true, false, 0, 0, 0, "Unknown engine response.", status),
            };
        }
        catch (DllNotFoundException)
        {
            return new EngineSessionOpenResult(false, false, 0, 0, 0, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineSessionOpenResult(false, false, 0, 0, 0, "Engine ABI mismatch", -101);
        }
    }

    public static EngineChunkReadResult ReadSourceSessionChunk(ulong sessionId, ulong offset, byte[] buffer)
    {
        if (buffer is null)
        {
            throw new ArgumentNullException(nameof(buffer));
        }

        try
        {
            var status = fr_read_source_session(
                sessionId,
                offset,
                buffer,
                (uint)buffer.Length,
                out var bytesRead);

            return status switch
            {
                0 => new EngineChunkReadResult(true, true, bytesRead, "Chunk read completed.", status),
                20 => new EngineChunkReadResult(true, false, 0, "Session not found.", status),
                10 => new EngineChunkReadResult(true, false, 0, "Invalid source path.", status),
                11 => new EngineChunkReadResult(true, false, 0, "Unsupported platform.", status),
                12 => new EngineChunkReadResult(true, false, 0, "Access denied.", status),
                13 => new EngineChunkReadResult(true, false, 0, "Source not found.", status),
                14 => new EngineChunkReadResult(true, false, 0, "Windows I/O error.", status),
                15 => new EngineChunkReadResult(true, false, 0, "Invalid read offset.", status),
                16 => new EngineChunkReadResult(true, false, 0, "Misaligned read parameters.", status),
                _ => new EngineChunkReadResult(true, false, 0, "Unknown engine response.", status),
            };
        }
        catch (DllNotFoundException)
        {
            return new EngineChunkReadResult(false, false, 0, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineChunkReadResult(false, false, 0, "Engine ABI mismatch", -101);
        }
    }

    public static int CloseSourceSession(ulong sessionId)
    {
        try
        {
            return fr_close_source_session(sessionId);
        }
        catch (DllNotFoundException)
        {
            return -100;
        }
        catch (EntryPointNotFoundException)
        {
            return -101;
        }
    }

    public static EngineNtfsBootProbeResult ProbeNtfsBootFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_ntfs_boot_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineNtfsBootMetadata(
                    nativeMetadata.BytesPerSector,
                    nativeMetadata.SectorsPerCluster,
                    nativeMetadata.ClusterSizeBytes,
                    nativeMetadata.FileRecordSizeBytes,
                    nativeMetadata.IndexRecordSizeBytes,
                    nativeMetadata.MftCluster,
                    nativeMetadata.MftOffsetBytes,
                    nativeMetadata.VolumeSizeBytes,
                    nativeMetadata.VolumeSerial);

                return new EngineNtfsBootProbeResult(
                    true,
                    true,
                    metadata,
                    "NTFS boot sector parsed.",
                    status);
            }

            return new EngineNtfsBootProbeResult(
                true,
                false,
                null,
                MapNtfsStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineNtfsBootProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineNtfsBootProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineRefsBootProbeResult ProbeRefsBootFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_refs_boot_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineRefsBootMetadata(
                    nativeMetadata.BytesPerSector,
                    nativeMetadata.SectorsPerCluster,
                    nativeMetadata.ClusterSizeBytes,
                    nativeMetadata.TotalSectors,
                    nativeMetadata.VolumeSizeBytes,
                    nativeMetadata.VolumeSerial);

                return new EngineRefsBootProbeResult(
                    true,
                    true,
                    metadata,
                    "ReFS boot sector parsed.",
                    status);
            }

            return new EngineRefsBootProbeResult(
                true,
                false,
                null,
                MapRefsStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineRefsBootProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRefsBootProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineRefsDeletedCandidatesResult GetRefsDeletedCandidatesFromSession(
        ulong sessionId,
        uint maxEntries = 512,
        int candidateCapacity = 128)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeRefsDeletedCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeRefsDeletedCandidate>();
            }
            else
            {
                buffer = new NativeRefsDeletedCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                }
            }

            var status = fr_get_refs_deleted_candidates_from_session(
                sessionId,
                maxEntries,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineRefsDeletedCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineRefsDeletedCandidate>(),
                    MapRefsStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var candidates = new List<EngineRefsDeletedCandidate>(count);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                candidates.Add(new EngineRefsDeletedCandidate(
                    Deleted: (candidate.Flags & RefsDeletedCandidateFlagDeleted) != 0,
                    ObjectId: candidate.ObjectId,
                    SizeBytes: candidate.SizeBytes,
                    Name: DecodeUtf8(candidate.Name),
                    ReconstructedPath: DecodeUtf8(candidate.ReconstructedPath)));
            }

            return new EngineRefsDeletedCandidatesResult(
                true,
                true,
                candidates,
                "ReFS deleted-candidate scan completed.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineRefsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineRefsDeletedCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRefsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineRefsDeletedCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineExtSuperblockProbeResult ProbeExtSuperblockFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_ext_superblock_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineExtSuperblockMetadata(
                    MapExtFilesystem(nativeMetadata.FilesystemKind),
                    nativeMetadata.BlockSizeBytes,
                    nativeMetadata.InodeSizeBytes,
                    nativeMetadata.InodesPerGroup,
                    nativeMetadata.TotalInodes,
                    nativeMetadata.TotalBlocks);

                return new EngineExtSuperblockProbeResult(
                    true,
                    true,
                    metadata,
                    "ext superblock parsed.",
                    status);
            }

            return new EngineExtSuperblockProbeResult(
                true,
                false,
                null,
                MapExtStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineExtSuperblockProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineExtSuperblockProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineExtDeletedCandidatesResult GetExtDeletedCandidatesFromSession(
        ulong sessionId,
        uint maxEntries = 512,
        int candidateCapacity = 128)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeExtDeletedCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeExtDeletedCandidate>();
            }
            else
            {
                buffer = new NativeExtDeletedCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                }
            }

            var status = fr_get_ext_deleted_candidates_from_session(
                sessionId,
                maxEntries,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineExtDeletedCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineExtDeletedCandidate>(),
                    MapExtStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var candidates = new List<EngineExtDeletedCandidate>(count);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                candidates.Add(new EngineExtDeletedCandidate(
                    Deleted: (candidate.Flags & ExtDeletedCandidateFlagDeleted) != 0,
                    IsDirectory: (candidate.Flags & ExtDeletedCandidateFlagDirectory) != 0,
                    InodeNumber: candidate.InodeNumber,
                    EntryOffsetBytes: candidate.EntryOffsetBytes,
                    SizeBytes: candidate.SizeBytes,
                    Name: DecodeUtf8(candidate.Name),
                    ReconstructedPath: DecodeUtf8(candidate.ReconstructedPath)));
            }

            return new EngineExtDeletedCandidatesResult(
                true,
                true,
                candidates,
                "ext deleted-candidate scan completed.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineExtDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineExtDeletedCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineExtDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineExtDeletedCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineEncryptedSourceListResult ListEncryptedSources(
        string sourcePath,
        RecoverySourceKind sourceKind)
    {
        try
        {
            var normalizedKind = NormalizeSourceKindForEngine(sourceKind);
            var entries = new NativeEncryptedSourceInfo[8];
            for (var i = 0; i < entries.Length; i++)
            {
                entries[i].Identifier = new byte[96];
                entries[i].DisplayName = new byte[160];
            }

            var status = fr_list_encrypted_sources(
                sourcePath,
                (int)normalizedKind,
                entries,
                (uint)entries.Length,
                out var written);

            if (status == 0)
            {
                var sources = new List<EngineEncryptedSource>(capacity: (int)written);
                for (var i = 0; i < written && i < entries.Length; i++)
                {
                    var item = entries[i];
                    var provider = MapEncryptedProvider(item.ProviderCode);
                    var identifier = DecodeUtf8(item.Identifier) ?? string.Empty;
                    var displayName = DecodeUtf8(item.DisplayName) ?? identifier;
                    var flags = item.Flags;
                    sources.Add(new EngineEncryptedSource(
                        Provider: provider,
                        Identifier: identifier,
                        DisplayName: string.IsNullOrWhiteSpace(displayName) ? provider : displayName,
                        Locked: (flags & EncryptedSourceFlagLocked) != 0,
                        SupportsPassword: (flags & EncryptedSourceFlagSupportsPassword) != 0,
                        SupportsRecoveryKey: (flags & EncryptedSourceFlagSupportsRecoveryKey) != 0,
                        SupportsKeyFile: (flags & EncryptedSourceFlagSupportsKeyFile) != 0));
                }

                return new EngineEncryptedSourceListResult(
                    true,
                    true,
                    sources,
                    sources.Count == 0 ? "No encrypted sources reported." : "Encrypted source metadata loaded.",
                    status);
            }

            return new EngineEncryptedSourceListResult(
                true,
                false,
                Array.Empty<EngineEncryptedSource>(),
                MapEncryptedSourceStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineEncryptedSourceListResult(
                false,
                false,
                Array.Empty<EngineEncryptedSource>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineEncryptedSourceListResult(
                false,
                false,
                Array.Empty<EngineEncryptedSource>(),
                "Engine encrypted-source API unavailable",
                -102);
        }
    }

    public static EngineEncryptedSourceUnlockResult UnlockEncryptedSource(
        string sourcePath,
        RecoverySourceKind sourceKind,
        string provider,
        string credentialKind,
        string credentialMaterial)
    {
        try
        {
            var normalizedKind = NormalizeSourceKindForEngine(sourceKind);
            var status = fr_unlock_encrypted_source(
                sourcePath,
                (int)normalizedKind,
                provider,
                credentialKind,
                credentialMaterial,
                out var unlocked);

            return status switch
            {
                0 => new EngineEncryptedSourceUnlockResult(
                    true,
                    true,
                    unlocked != 0,
                    provider,
                    unlocked != 0 ? "Encrypted source unlocked." : "Unlock request completed but source remained locked.",
                    status),
                _ => new EngineEncryptedSourceUnlockResult(
                    true,
                    false,
                    false,
                    provider,
                    MapEncryptedSourceStatusMessage(status),
                    status),
            };
        }
        catch (DllNotFoundException)
        {
            return new EngineEncryptedSourceUnlockResult(
                false,
                false,
                false,
                provider,
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineEncryptedSourceUnlockResult(
                false,
                false,
                false,
                provider,
                "Engine encrypted-source API unavailable",
                -102);
        }
    }

    public static EngineEncryptedSourceLockResult LockEncryptedSource(
        string sourcePath,
        RecoverySourceKind sourceKind,
        string provider)
    {
        try
        {
            var normalizedKind = NormalizeSourceKindForEngine(sourceKind);
            var status = fr_lock_encrypted_source(
                sourcePath,
                (int)normalizedKind,
                provider,
                out var locked);

            return status switch
            {
                0 => new EngineEncryptedSourceLockResult(
                    true,
                    true,
                    locked != 0,
                    provider,
                    locked != 0 ? "Encrypted source lock requested." : "Encrypted source lock completed with no lock-state change.",
                    status),
                _ => new EngineEncryptedSourceLockResult(
                    true,
                    false,
                    false,
                    provider,
                    MapEncryptedSourceStatusMessage(status),
                    status),
            };
        }
        catch (DllNotFoundException)
        {
            return new EngineEncryptedSourceLockResult(
                false,
                false,
                false,
                provider,
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineEncryptedSourceLockResult(
                false,
                false,
                false,
                provider,
                "Engine encrypted-source API unavailable",
                -102);
        }
    }

    public static EngineXfsSuperblockProbeResult ProbeXfsSuperblockFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_xfs_superblock_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineXfsSuperblockMetadata(
                    nativeMetadata.BlockSizeBytes,
                    nativeMetadata.InodeSizeBytes,
                    nativeMetadata.AgCount,
                    nativeMetadata.DataBlocks);

                return new EngineXfsSuperblockProbeResult(
                    true,
                    true,
                    metadata,
                    "XFS superblock parsed.",
                    status);
            }

            return new EngineXfsSuperblockProbeResult(
                true,
                false,
                null,
                MapXfsStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineXfsSuperblockProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineXfsSuperblockProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineXfsDeletedCandidatesResult GetXfsDeletedCandidatesFromSession(
        ulong sessionId,
        uint maxEntries = 512,
        int candidateCapacity = 128)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeXfsDeletedCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeXfsDeletedCandidate>();
            }
            else
            {
                buffer = new NativeXfsDeletedCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                }
            }

            var status = fr_get_xfs_deleted_candidates_from_session(
                sessionId,
                maxEntries,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineXfsDeletedCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineXfsDeletedCandidate>(),
                    MapXfsStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var candidates = new List<EngineXfsDeletedCandidate>(count);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                candidates.Add(new EngineXfsDeletedCandidate(
                    Deleted: (candidate.Flags & XfsDeletedCandidateFlagDeleted) != 0,
                    IsDirectory: (candidate.Flags & XfsDeletedCandidateFlagDirectory) != 0,
                    InodeNumber: candidate.InodeNumber,
                    SizeBytes: candidate.SizeBytes,
                    Name: DecodeUtf8(candidate.Name),
                    ReconstructedPath: DecodeUtf8(candidate.ReconstructedPath)));
            }

            return new EngineXfsDeletedCandidatesResult(
                true,
                true,
                candidates,
                "XFS deleted-candidate scan completed.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineXfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineXfsDeletedCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineXfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineXfsDeletedCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineUfsSuperblockProbeResult ProbeUfsSuperblockFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_ufs_superblock_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineUfsSuperblockMetadata(
                    nativeMetadata.Magic,
                    nativeMetadata.BlockSizeBytes,
                    nativeMetadata.FragmentSizeBytes,
                    nativeMetadata.TotalBlocks);

                return new EngineUfsSuperblockProbeResult(
                    true,
                    true,
                    metadata,
                    "UFS superblock parsed.",
                    status);
            }

            return new EngineUfsSuperblockProbeResult(
                true,
                false,
                null,
                MapUfsStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineUfsSuperblockProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineUfsSuperblockProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineUfsDeletedCandidatesResult GetUfsDeletedCandidatesFromSession(
        ulong sessionId,
        uint maxEntries = 512,
        int candidateCapacity = 128)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeUfsDeletedCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeUfsDeletedCandidate>();
            }
            else
            {
                buffer = new NativeUfsDeletedCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                }
            }

            var status = fr_get_ufs_deleted_candidates_from_session(
                sessionId,
                maxEntries,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineUfsDeletedCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineUfsDeletedCandidate>(),
                    MapUfsStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var candidates = new List<EngineUfsDeletedCandidate>(count);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                candidates.Add(new EngineUfsDeletedCandidate(
                    Deleted: (candidate.Flags & UfsDeletedCandidateFlagDeleted) != 0,
                    IsDirectory: (candidate.Flags & UfsDeletedCandidateFlagDirectory) != 0,
                    InodeNumber: candidate.InodeNumber,
                    SizeBytes: candidate.SizeBytes,
                    Name: DecodeUtf8(candidate.Name),
                    ReconstructedPath: DecodeUtf8(candidate.ReconstructedPath)));
            }

            return new EngineUfsDeletedCandidatesResult(
                true,
                true,
                candidates,
                "UFS deleted-candidate scan completed.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineUfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineUfsDeletedCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineUfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineUfsDeletedCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineApfsContainerProbeResult ProbeApfsContainerFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_apfs_container_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineApfsContainerMetadata(
                    nativeMetadata.BlockSizeBytes,
                    nativeMetadata.BlockCount,
                    nativeMetadata.Features,
                    nativeMetadata.IncompatFeatures,
                    nativeMetadata.ContainerObjectId);

                return new EngineApfsContainerProbeResult(
                    true,
                    true,
                    metadata,
                    "APFS container superblock parsed.",
                    status);
            }

            return new EngineApfsContainerProbeResult(
                true,
                false,
                null,
                MapApfsStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineApfsContainerProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineApfsContainerProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineApfsDeletedCandidatesResult GetApfsDeletedCandidatesFromSession(
        ulong sessionId,
        uint maxEntries = 512,
        int candidateCapacity = 128)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeApfsDeletedCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeApfsDeletedCandidate>();
            }
            else
            {
                buffer = new NativeApfsDeletedCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                }
            }

            var status = fr_get_apfs_deleted_candidates_from_session(
                sessionId,
                maxEntries,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineApfsDeletedCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineApfsDeletedCandidate>(),
                    MapApfsStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var candidates = new List<EngineApfsDeletedCandidate>(count);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                candidates.Add(new EngineApfsDeletedCandidate(
                    Deleted: (candidate.Flags & ApfsDeletedCandidateFlagDeleted) != 0,
                    IsDirectory: (candidate.Flags & ApfsDeletedCandidateFlagDirectory) != 0,
                    Cnid: candidate.Cnid,
                    SizeBytes: candidate.SizeBytes,
                    Name: DecodeUtf8(candidate.Name),
                    ReconstructedPath: DecodeUtf8(candidate.ReconstructedPath)));
            }

            return new EngineApfsDeletedCandidatesResult(
                true,
                true,
                candidates,
                "APFS deleted-candidate scan completed.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineApfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineApfsDeletedCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineApfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineApfsDeletedCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineHfsVolumeProbeResult ProbeHfsVolumeHeaderFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_hfs_volume_header_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineHfsVolumeMetadata(
                    nativeMetadata.Signature,
                    nativeMetadata.Version,
                    nativeMetadata.BlockSizeBytes,
                    nativeMetadata.TotalBlocks,
                    nativeMetadata.FileCount,
                    nativeMetadata.FolderCount);

                return new EngineHfsVolumeProbeResult(
                    true,
                    true,
                    metadata,
                    "HFS+ volume header parsed.",
                    status);
            }

            return new EngineHfsVolumeProbeResult(
                true,
                false,
                null,
                MapHfsStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineHfsVolumeProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineHfsVolumeProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineHfsDeletedCandidatesResult GetHfsDeletedCandidatesFromSession(
        ulong sessionId,
        uint maxEntries = 512,
        int candidateCapacity = 128)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeHfsDeletedCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeHfsDeletedCandidate>();
            }
            else
            {
                buffer = new NativeHfsDeletedCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                }
            }

            var status = fr_get_hfs_deleted_candidates_from_session(
                sessionId,
                maxEntries,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineHfsDeletedCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineHfsDeletedCandidate>(),
                    MapHfsStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var candidates = new List<EngineHfsDeletedCandidate>(count);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                candidates.Add(new EngineHfsDeletedCandidate(
                    Deleted: (candidate.Flags & HfsDeletedCandidateFlagDeleted) != 0,
                    IsDirectory: (candidate.Flags & HfsDeletedCandidateFlagDirectory) != 0,
                    Cnid: candidate.Cnid,
                    SizeBytes: candidate.SizeBytes,
                    Name: DecodeUtf8(candidate.Name),
                    ReconstructedPath: DecodeUtf8(candidate.ReconstructedPath)));
            }

            return new EngineHfsDeletedCandidatesResult(
                true,
                true,
                candidates,
                "HFS+ deleted-candidate scan completed.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineHfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineHfsDeletedCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineHfsDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineHfsDeletedCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineFatBootProbeResult ProbeFatBootFromSession(ulong sessionId)
    {
        try
        {
            var status = fr_probe_fat_boot_from_session(sessionId, out var nativeMetadata);
            if (status == 0)
            {
                var metadata = new EngineFatBootMetadata(
                    MapFatFilesystem(nativeMetadata.FilesystemKind),
                    nativeMetadata.BytesPerSector,
                    nativeMetadata.SectorsPerCluster,
                    nativeMetadata.FatCount,
                    nativeMetadata.ClusterSizeBytes,
                    nativeMetadata.TotalSectors,
                    nativeMetadata.RootDirFirstCluster,
                    nativeMetadata.FatOffsetBytes,
                    nativeMetadata.DataRegionOffsetBytes,
                    nativeMetadata.VolumeSerial);

                return new EngineFatBootProbeResult(
                    true,
                    true,
                    metadata,
                    "FAT/exFAT boot sector parsed.",
                    status);
            }

            return new EngineFatBootProbeResult(
                true,
                false,
                null,
                MapFatStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineFatBootProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineFatBootProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineFatDeletedCandidatesResult GetFatDeletedCandidatesFromSession(
        ulong sessionId,
        uint maxEntries = 512,
        int candidateCapacity = 128)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeFatDeletedCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeFatDeletedCandidate>();
            }
            else
            {
                buffer = new NativeFatDeletedCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                }
            }

            var status = fr_get_fat_deleted_candidates_from_session(
                sessionId,
                maxEntries,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineFatDeletedCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineFatDeletedCandidate>(),
                    MapFatStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var candidates = new List<EngineFatDeletedCandidate>(count);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                candidates.Add(new EngineFatDeletedCandidate(
                    Deleted: (candidate.Flags & FatDeletedCandidateFlagDeleted) != 0,
                    IsDirectory: (candidate.Flags & FatDeletedCandidateFlagDirectory) != 0,
                    StartCluster: candidate.StartCluster,
                    SizeBytes: candidate.SizeBytes,
                    Name: DecodeUtf8(candidate.Name),
                    ReconstructedPath: DecodeUtf8(candidate.ReconstructedPath)));
            }

            var message = written > (uint)buffer.Length
                ? $"FAT/exFAT deleted-entry quick scan completed (returned {count} of {written}; increase candidate capacity to load more)."
                : "FAT/exFAT deleted-entry quick scan completed.";

            return new EngineFatDeletedCandidatesResult(
                true,
                true,
                candidates,
                message,
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineFatDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineFatDeletedCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineFatDeletedCandidatesResult(
                false,
                false,
                Array.Empty<EngineFatDeletedCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRaidLayoutProbeResult ProbeRaidLayoutFromSession(
        ulong sessionId,
        EngineRaidManualOverride? manualOverride = null)
    {
        NativeRaidManualOverride? nativeOverride;
        try
        {
            nativeOverride = BuildNativeRaidManualOverride(manualOverride);
        }
        catch (ArgumentException ex)
        {
            return new EngineRaidLayoutProbeResult(true, false, null, ex.Message, 142);
        }

        try
        {
            var hasOverride = nativeOverride.HasValue;
            int status;
            NativeRaidLayout nativeLayout;
            if (hasOverride)
            {
                var overrideValue = nativeOverride.GetValueOrDefault();
                status = fr_probe_raid_layout_from_session(sessionId, ref overrideValue, out nativeLayout);
            }
            else
            {
                status = fr_probe_raid_layout_from_session(sessionId, IntPtr.Zero, out nativeLayout);
            }

            if (status == 0)
            {
                var metadata = MapNativeRaidLayout(nativeLayout);

                return new EngineRaidLayoutProbeResult(
                    true,
                    true,
                    metadata,
                    "RAID layout metadata parsed.",
                    status);
            }

            return new EngineRaidLayoutProbeResult(
                true,
                false,
                null,
                MapRaidStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineRaidLayoutProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRaidLayoutProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineVirtualRaidSessionOpenResult OpenVirtualRaidSession(
        IReadOnlyList<ulong> memberSessionIds,
        EngineRaidManualOverride? manualOverride = null)
    {
        if (memberSessionIds is null)
        {
            throw new ArgumentNullException(nameof(memberSessionIds));
        }
        if (memberSessionIds.Count < 2 || memberSessionIds.Count > RaidLayoutMaxMembers)
        {
            return new EngineVirtualRaidSessionOpenResult(
                true,
                false,
                0,
                0,
                null,
                "RAID virtual assembly requires between 2 and 32 member sessions.",
                142);
        }

        var memberSessionIdBuffer = new ulong[memberSessionIds.Count];
        for (var index = 0; index < memberSessionIds.Count; index++)
        {
            memberSessionIdBuffer[index] = memberSessionIds[index];
        }

        NativeRaidManualOverride? nativeOverride;
        try
        {
            nativeOverride = BuildNativeRaidManualOverride(manualOverride);
        }
        catch (ArgumentException ex)
        {
            return new EngineVirtualRaidSessionOpenResult(true, false, 0, 0, null, ex.Message, 142);
        }

        try
        {
            var hasOverride = nativeOverride.HasValue;
            int status;
            NativeRaidLayout nativeLayout;
            ulong virtualSessionId;
            ulong sizeBytes;

            if (hasOverride)
            {
                var overrideValue = nativeOverride.GetValueOrDefault();
                status = fr_open_virtual_raid_session(
                    memberSessionIdBuffer,
                    (uint)memberSessionIdBuffer.Length,
                    ref overrideValue,
                    out virtualSessionId,
                    out sizeBytes,
                    out nativeLayout);
            }
            else
            {
                status = fr_open_virtual_raid_session(
                    memberSessionIdBuffer,
                    (uint)memberSessionIdBuffer.Length,
                    IntPtr.Zero,
                    out virtualSessionId,
                    out sizeBytes,
                    out nativeLayout);
            }

            if (status == 0)
            {
                return new EngineVirtualRaidSessionOpenResult(
                    true,
                    true,
                    virtualSessionId,
                    sizeBytes,
                    MapNativeRaidLayout(nativeLayout),
                    "Virtual RAID source assembled.",
                    status);
            }

            return new EngineVirtualRaidSessionOpenResult(
                true,
                false,
                0,
                0,
                null,
                MapRaidStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineVirtualRaidSessionOpenResult(false, false, 0, 0, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineVirtualRaidSessionOpenResult(false, false, 0, 0, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineRaidLayoutProbeResult ProbeVirtualRaidSession(ulong virtualSessionId)
    {
        try
        {
            var status = fr_probe_virtual_raid_session(virtualSessionId, out var nativeLayout);
            if (status == 0)
            {
                return new EngineRaidLayoutProbeResult(
                    true,
                    true,
                    MapNativeRaidLayout(nativeLayout),
                    "Virtual RAID layout metadata loaded.",
                    status);
            }

            return new EngineRaidLayoutProbeResult(
                true,
                false,
                null,
                MapRaidStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineRaidLayoutProbeResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRaidLayoutProbeResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static int CloseVirtualRaidSession(ulong virtualSessionId)
    {
        try
        {
            return fr_close_virtual_raid_session(virtualSessionId);
        }
        catch (DllNotFoundException)
        {
            return -100;
        }
        catch (EntryPointNotFoundException)
        {
            return -101;
        }
    }

    public static EngineRaidLogicalMappingResult MapRaidLogicalOffset(
        EngineRaidLayoutMetadata layout,
        ulong logicalOffsetBytes)
    {
        if (layout is null)
        {
            throw new ArgumentNullException(nameof(layout));
        }

        NativeRaidLayout nativeLayout;
        try
        {
            nativeLayout = BuildNativeRaidLayout(layout);
        }
        catch (ArgumentException ex)
        {
            return new EngineRaidLogicalMappingResult(true, false, null, ex.Message, 142);
        }

        try
        {
            var status = fr_map_raid_logical_offset(ref nativeLayout, logicalOffsetBytes, out var nativeMapping);
            if (status == 0)
            {
                var mapping = new EngineRaidLogicalMapping(
                    MemberIndex: nativeMapping.MemberIndex,
                    MemberOffsetBytes: nativeMapping.MemberOffsetBytes,
                    ParityMemberIndex: nativeMapping.HasParityMember != 0 ? nativeMapping.ParityMemberIndex : null);

                return new EngineRaidLogicalMappingResult(
                    true,
                    true,
                    mapping,
                    "RAID logical mapping resolved.",
                    status);
            }

            return new EngineRaidLogicalMappingResult(
                true,
                false,
                null,
                MapRaidStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineRaidLogicalMappingResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRaidLogicalMappingResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineRaidDegradedAssessmentResult AssessRaidDegradedLayout(
        EngineRaidLayoutMetadata layout,
        IReadOnlyList<uint>? missingMembers,
        uint sampleCount = 64)
    {
        ArgumentNullException.ThrowIfNull(layout);

        NativeRaidLayout nativeLayout;
        try
        {
            nativeLayout = BuildNativeRaidLayout(layout);
        }
        catch (ArgumentException ex)
        {
            return new EngineRaidDegradedAssessmentResult(true, false, null, ex.Message, 142);
        }

        var missing = (missingMembers ?? Array.Empty<uint>()).ToArray();
        if (missing.Length > RaidLayoutMaxMembers)
        {
            return new EngineRaidDegradedAssessmentResult(
                true,
                false,
                null,
                "Missing-member list exceeds RAID max member count.",
                142);
        }

        try
        {
            var status = fr_assess_raid_degraded_layout(
                ref nativeLayout,
                missing,
                checked((uint)missing.Length),
                sampleCount,
                out var nativeAssessment);
            if (status == 0)
            {
                var assessment = new EngineRaidDegradedAssessment(
                    MissingMemberCount: nativeAssessment.MissingMemberCount,
                    SampleCount: nativeAssessment.SampleCount,
                    RecoverableSampleCount: nativeAssessment.RecoverableSampleCount,
                    RecoverabilityPercent: nativeAssessment.RecoverabilityPercent,
                    ConfidencePenalty: nativeAssessment.ConfidencePenalty,
                    Recommendation: DecodeUtf8(nativeAssessment.Recommendation) ?? string.Empty);
                return new EngineRaidDegradedAssessmentResult(
                    true,
                    true,
                    assessment,
                    "RAID degraded assessment completed.",
                    0);
            }

            return new EngineRaidDegradedAssessmentResult(
                true,
                false,
                null,
                MapRaidStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineRaidDegradedAssessmentResult(false, false, null, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRaidDegradedAssessmentResult(false, false, null, "Engine ABI mismatch", -101);
        }
    }

    public static EngineNtfsQuickScanResult QuickScanNtfsFromSession(ulong sessionId, uint maxRecords)
    {
        try
        {
            var status = fr_quick_scan_ntfs_from_session(sessionId, maxRecords, out var nativeSummary);
            if (status == 0)
            {
                return new EngineNtfsQuickScanResult(
                    true,
                    true,
                    nativeSummary.ParsedRecords,
                    nativeSummary.ParseFailures,
                    nativeSummary.ResidentAttributeCount,
                    nativeSummary.NonResidentAttributeCount,
                    nativeSummary.DeletedRecords,
                    nativeSummary.DirectoryRecords,
                    nativeSummary.NamedRecords,
                    nativeSummary.RecordsWithNonResidentData,
                    nativeSummary.UsnEnrichedRecords,
                    nativeSummary.UsnGhostRecords,
                    "NTFS metadata quick scan completed.",
                    status);
            }

            return new EngineNtfsQuickScanResult(
                true,
                false,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                MapNtfsStatusMessage(status),
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineNtfsQuickScanResult(false, false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "Engine unavailable", -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineNtfsQuickScanResult(false, false, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "Engine ABI mismatch", -101);
        }
    }

    public static EngineNtfsQuickScanCandidatesResult GetNtfsQuickScanCandidatesFromSession(
        ulong sessionId,
        uint maxRecords,
        int candidateCapacity = 128)
    {
        return GetNtfsQuickScanCandidatesFromSessionCore(
            sessionId,
            maxRecords,
            candidateCapacity,
            usnJournalBytes: null);
    }

    public static EngineNtfsQuickScanCandidatesResult GetNtfsQuickScanCandidatesFromSessionWithUsn(
        ulong sessionId,
        uint maxRecords,
        byte[] usnJournalBytes,
        int candidateCapacity = 128)
    {
        return GetNtfsQuickScanCandidatesFromSessionCore(
            sessionId,
            maxRecords,
            candidateCapacity,
            usnJournalBytes);
    }

    private static EngineNtfsQuickScanCandidatesResult GetNtfsQuickScanCandidatesFromSessionCore(
        ulong sessionId,
        uint maxRecords,
        int candidateCapacity,
        byte[]? usnJournalBytes)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            NativeNtfsQuickScanCandidate[] buffer;
            if (candidateCapacity == 0)
            {
                buffer = Array.Empty<NativeNtfsQuickScanCandidate>();
            }
            else
            {
                buffer = new NativeNtfsQuickScanCandidate[candidateCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].Name = new byte[128];
                    buffer[i].ReconstructedPath = new byte[256];
                    buffer[i].ConfidenceReason = new byte[256];
                }
            }

            int status;
            uint written;
            if (usnJournalBytes is { Length: > 0 })
            {
                status = fr_get_ntfs_quick_scan_candidates_from_session_with_usn(
                    sessionId,
                    maxRecords,
                    buffer,
                    (uint)buffer.Length,
                    out written,
                    usnJournalBytes,
                    (uint)usnJournalBytes.Length);
            }
            else
            {
                status = fr_get_ntfs_quick_scan_candidates_from_session(
                    sessionId,
                    maxRecords,
                    buffer,
                    (uint)buffer.Length,
                    out written);
            }

            if (status != 0)
            {
                return new EngineNtfsQuickScanCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineNtfsQuickScanCandidate>(),
                    MapNtfsStatusMessage(status),
                    status);
            }

            var results = new List<EngineNtfsQuickScanCandidate>((int)Math.Min(written, (uint)buffer.Length));
            var count = (int)Math.Min(written, (uint)buffer.Length);
            for (var i = 0; i < count; i++)
            {
                var candidate = buffer[i];
                var name = DecodeUtf8(candidate.Name);
                var path = DecodeUtf8(candidate.ReconstructedPath);
                var confidenceReason = DecodeUtf8(candidate.ConfidenceReason) ?? "Engine confidence reason unavailable.";
                var flags = candidate.Flags;
                var hasFileMetadata = (flags & CandidateFlagHasFileMetadata) != 0;

                results.Add(new EngineNtfsQuickScanCandidate(
                    candidate.RecordNumber,
                    (flags & CandidateFlagInUse) != 0,
                    (flags & CandidateFlagDeleted) != 0,
                    (flags & CandidateFlagGhostRecord) != 0,
                    (flags & CandidateFlagDirectory) != 0,
                    (flags & CandidateFlagNonResidentData) != 0,
                    (flags & CandidateFlagHasNamedDataStream) != 0,
                    (flags & CandidateFlagCompressed) != 0,
                    (flags & CandidateFlagSparse) != 0,
                    (flags & CandidateFlagEncrypted) != 0,
                    candidate.ParentRecordNumber == 0 ? null : candidate.ParentRecordNumber,
                    name,
                    path,
                    hasFileMetadata ? candidate.DataSizeBytes : null,
                    hasFileMetadata ? candidate.AllocatedSizeBytes : null,
                    hasFileMetadata ? candidate.FileAttributes : null,
                    hasFileMetadata ? candidate.CreatedFileTimeUtc : null,
                    hasFileMetadata ? candidate.ModifiedFileTimeUtc : null,
                    hasFileMetadata ? candidate.MftModifiedFileTimeUtc : null,
                    hasFileMetadata ? candidate.AccessedFileTimeUtc : null,
                    MapEvidenceSources(flags),
                    MapConfidenceTier(candidate.ConfidenceTier),
                    confidenceReason));
            }

            return new EngineNtfsQuickScanCandidatesResult(
                true,
                true,
                results,
                "NTFS quick-scan candidates loaded.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineNtfsQuickScanCandidatesResult(
                false,
                false,
                Array.Empty<EngineNtfsQuickScanCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineNtfsQuickScanCandidatesResult(
                false,
                false,
                Array.Empty<EngineNtfsQuickScanCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineCarveCandidatesResult GetCarveCandidatesFromSession(
        ulong sessionId,
        uint familyFlags,
        ulong maxScanBytes,
        int candidateCapacity = 256)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            var buffer = AllocateCarveBuffer(candidateCapacity);
            var status = fr_get_carve_candidates_from_session(
                sessionId,
                familyFlags,
                maxScanBytes,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineCarveCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineCarveCandidate>(),
                    MapCarveStatusMessage(status),
                    status);
            }

            var results = DecodeCarveCandidates(buffer, written);
            return new EngineCarveCandidatesResult(
                true,
                true,
                results,
                "Carving candidates loaded.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineCarveCandidatesResult(
                false,
                false,
                Array.Empty<EngineCarveCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineCarveCandidatesResult(
                false,
                false,
                Array.Empty<EngineCarveCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineCarveCandidatesResult GetCarveCandidatesFromSessionWindow(
        ulong sessionId,
        uint familyFlags,
        ulong windowOffsetBytes,
        ulong windowLengthBytes,
        int candidateCapacity = 256)
    {
        if (candidateCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(candidateCapacity));
        }

        try
        {
            var buffer = AllocateCarveBuffer(candidateCapacity);
            var status = fr_get_carve_candidates_from_session_window(
                sessionId,
                familyFlags,
                windowOffsetBytes,
                windowLengthBytes,
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineCarveCandidatesResult(
                    true,
                    false,
                    Array.Empty<EngineCarveCandidate>(),
                    MapCarveStatusMessage(status),
                    status);
            }

            var results = DecodeCarveCandidates(buffer, written);

            return new EngineCarveCandidatesResult(
                true,
                true,
                results,
                "Carving candidates loaded (stream window).",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineCarveCandidatesResult(
                false,
                false,
                Array.Empty<EngineCarveCandidate>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            if (windowOffsetBytes == 0)
            {
                return GetCarveCandidatesFromSession(sessionId, familyFlags, windowLengthBytes, candidateCapacity);
            }

            return new EngineCarveCandidatesResult(
                false,
                false,
                Array.Empty<EngineCarveCandidate>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    private static NativeCarveCandidate[] AllocateCarveBuffer(int candidateCapacity)
    {
        if (candidateCapacity == 0)
        {
            return Array.Empty<NativeCarveCandidate>();
        }

        var buffer = new NativeCarveCandidate[candidateCapacity];
        for (var i = 0; i < buffer.Length; i++)
        {
            buffer[i].Format = new byte[16];
            buffer[i].SuggestedName = new byte[128];
            buffer[i].ConfidenceReason = new byte[256];
        }

        return buffer;
    }

    private static List<EngineCarveCandidate> DecodeCarveCandidates(NativeCarveCandidate[] buffer, uint written)
    {
        var results = new List<EngineCarveCandidate>((int)Math.Min(written, (uint)buffer.Length));
        var count = (int)Math.Min(written, (uint)buffer.Length);
        for (var i = 0; i < count; i++)
        {
            var candidate = buffer[i];
            var format = DecodeUtf8(candidate.Format) ?? "bin";
            var suggestedName = DecodeUtf8(candidate.SuggestedName) ?? $"carve_{candidate.OffsetBytes:X16}.{format}";
            var confidenceReason = DecodeUtf8(candidate.ConfidenceReason) ?? "Signature-based carving candidate.";
            var partial = (candidate.Flags & CarveCandidateFlagPartial) != 0;
            results.Add(new EngineCarveCandidate(
                candidate.OffsetBytes,
                candidate.LengthBytes,
                partial,
                format,
                suggestedName,
                MapConfidenceTier(candidate.ConfidenceTier),
                confidenceReason));
        }

        return results;
    }

    public static EngineVssSnapshotListResult ListVssSnapshots(int snapshotCapacity = 64)
    {
        if (snapshotCapacity < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(snapshotCapacity));
        }

        try
        {
            NativeVssSnapshot[] buffer;
            if (snapshotCapacity == 0)
            {
                buffer = Array.Empty<NativeVssSnapshot>();
            }
            else
            {
                buffer = new NativeVssSnapshot[snapshotCapacity];
                for (var i = 0; i < buffer.Length; i++)
                {
                    buffer[i].SnapshotId = new byte[96];
                    buffer[i].VolumeName = new byte[260];
                    buffer[i].DeviceObject = new byte[260];
                    buffer[i].InstallTimeUtc = new byte[64];
                    buffer[i].SnapshotPath = new byte[260];
                }
            }

            var status = fr_list_vss_snapshots(
                buffer,
                (uint)buffer.Length,
                out var written);

            if (status != 0)
            {
                return new EngineVssSnapshotListResult(
                    true,
                    false,
                    Array.Empty<EngineVssSnapshot>(),
                    MapVssStatusMessage(status),
                    status);
            }

            var count = (int)Math.Min(written, (uint)buffer.Length);
            var snapshots = new List<EngineVssSnapshot>(count);
            for (var i = 0; i < count; i++)
            {
                var current = buffer[i];
                var snapshotId = DecodeUtf8(current.SnapshotId);
                var deviceObject = DecodeUtf8(current.DeviceObject);
                var snapshotPath = DecodeUtf8(current.SnapshotPath);
                if (string.IsNullOrWhiteSpace(snapshotId) ||
                    string.IsNullOrWhiteSpace(deviceObject) ||
                    string.IsNullOrWhiteSpace(snapshotPath))
                {
                    continue;
                }

                snapshots.Add(new EngineVssSnapshot(
                    snapshotId,
                    DecodeUtf8(current.VolumeName),
                    deviceObject,
                    DecodeUtf8(current.InstallTimeUtc),
                    snapshotPath));
            }

            return new EngineVssSnapshotListResult(
                true,
                true,
                snapshots,
                "VSS snapshots loaded.",
                status);
        }
        catch (DllNotFoundException)
        {
            return new EngineVssSnapshotListResult(
                false,
                false,
                Array.Empty<EngineVssSnapshot>(),
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineVssSnapshotListResult(
                false,
                false,
                Array.Empty<EngineVssSnapshot>(),
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverNtfsCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        uint recordNumber,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverNtfsCandidateToFile(open.SessionId, recordNumber, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverNtfsCandidateToFile(
        ulong sessionId,
        uint recordNumber,
        string outputPath)
    {
        try
        {
            try
            {
                var status = fr_recover_ntfs_candidate_to_file_ex(
                    sessionId,
                    recordNumber,
                    outputPath,
                    out var bytesWritten,
                    out var partial,
                    out var diagnosticsFlags);
                return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags);
            }
            catch (EntryPointNotFoundException)
            {
                var status = fr_recover_ntfs_candidate_to_file(
                    sessionId,
                    recordNumber,
                    outputPath,
                    out var bytesWritten,
                    out var partial);
                return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
            }
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverFatCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        uint startCluster,
        ulong sizeBytes,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverFatCandidateToFile(open.SessionId, startCluster, sizeBytes, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverFatCandidateToFile(
        ulong sessionId,
        uint startCluster,
        ulong sizeBytes,
        string outputPath)
    {
        try
        {
            var status = fr_recover_fat_candidate_to_file(
                sessionId,
                startCluster,
                sizeBytes,
                outputPath,
                out var bytesWritten,
                out var partial);
            return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverExtCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        ulong inodeNumber,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverExtCandidateToFile(open.SessionId, inodeNumber, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverExtCandidateToFile(
        ulong sessionId,
        ulong inodeNumber,
        string outputPath)
    {
        try
        {
            var status = fr_recover_ext_candidate_to_file(
                sessionId,
                inodeNumber,
                outputPath,
                out var bytesWritten,
                out var partial);
            return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverRefsCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        ulong objectId,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverRefsCandidateToFile(open.SessionId, objectId, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverRefsCandidateToFile(
        ulong sessionId,
        ulong objectId,
        string outputPath)
    {
        try
        {
            var status = fr_recover_refs_candidate_to_file(
                sessionId,
                objectId,
                outputPath,
                out var bytesWritten,
                out var partial);
            return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverApfsCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        ulong cnid,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverApfsCandidateToFile(open.SessionId, cnid, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverApfsCandidateToFile(
        ulong sessionId,
        ulong cnid,
        string outputPath)
    {
        try
        {
            var status = fr_recover_apfs_candidate_to_file(
                sessionId,
                cnid,
                outputPath,
                out var bytesWritten,
                out var partial);
            return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverHfsCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        ulong cnid,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverHfsCandidateToFile(open.SessionId, cnid, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverHfsCandidateToFile(
        ulong sessionId,
        ulong cnid,
        string outputPath)
    {
        if (cnid == 0 || cnid > uint.MaxValue)
        {
            return BuildRecoverResult(170, 0, false, diagnosticsFlags: 0);
        }

        try
        {
            var status = fr_recover_hfs_candidate_to_file(
                sessionId,
                (uint)cnid,
                outputPath,
                out var bytesWritten,
                out var partial);
            return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverXfsCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        ulong inodeNumber,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverXfsCandidateToFile(open.SessionId, inodeNumber, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverXfsCandidateToFile(
        ulong sessionId,
        ulong inodeNumber,
        string outputPath)
    {
        try
        {
            var status = fr_recover_xfs_candidate_to_file(
                sessionId,
                inodeNumber,
                outputPath,
                out var bytesWritten,
                out var partial);
            return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    public static EngineRecoverCandidateResult RecoverUfsCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        ulong inodeNumber,
        string outputPath)
    {
        var open = OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            return RecoverUfsCandidateToFile(open.SessionId, inodeNumber, outputPath);
        }
        finally
        {
            CloseSourceSession(open.SessionId);
        }
    }

    public static EngineRecoverCandidateResult RecoverUfsCandidateToFile(
        ulong sessionId,
        ulong inodeNumber,
        string outputPath)
    {
        if (inodeNumber == 0 || inodeNumber > uint.MaxValue)
        {
            return BuildRecoverResult(170, 0, false, diagnosticsFlags: 0);
        }

        try
        {
            var status = fr_recover_ufs_candidate_to_file(
                sessionId,
                (uint)inodeNumber,
                outputPath,
                out var bytesWritten,
                out var partial);
            return BuildRecoverResult(status, bytesWritten, partial != 0, diagnosticsFlags: 0);
        }
        catch (DllNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine unavailable",
                -100);
        }
        catch (EntryPointNotFoundException)
        {
            return new EngineRecoverCandidateResult(
                false,
                false,
                false,
                0,
                0,
                "No diagnostics available.",
                "Engine ABI mismatch",
                -101);
        }
    }

    private static uint TryGetSourceSessionAlignment(ulong sessionId)
    {
        try
        {
            var status = fr_get_source_session_alignment(sessionId, out var alignmentBytes);
            return status == 0 ? alignmentBytes : 0;
        }
        catch (DllNotFoundException)
        {
            return 0;
        }
        catch (EntryPointNotFoundException)
        {
            return 0;
        }
    }

    private static RecoverySourceKind NormalizeSourceKindForEngine(RecoverySourceKind sourceKind)
    {
        return sourceKind == RecoverySourceKind.Partition
            ? RecoverySourceKind.Volume
            : sourceKind;
    }

    private static string MapNtfsStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            30 => "Source does not contain a valid NTFS boot sector.",
            31 => "Source read ended before required metadata could be loaded.",
            32 => "NTFS file record size is unsupported.",
            33 => "NTFS metadata offset arithmetic overflowed.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            51 => "USN journal payload is truncated.",
            52 => "USN journal payload is malformed.",
            53 => "USN journal version is unsupported.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapRefsStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required metadata could be loaded.",
            80 => "Source does not contain a valid ReFS boot sector.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapExtStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required metadata could be loaded.",
            90 => "Source does not contain a valid ext superblock.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            -4 => "Invalid carve window offset/length.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapXfsStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required metadata could be loaded.",
            120 => "Source does not contain a valid XFS superblock.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapUfsStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required metadata could be loaded.",
            130 => "Source does not contain a valid UFS superblock.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapApfsStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required metadata could be loaded.",
            100 => "Source does not contain a valid APFS container superblock.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapHfsStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required metadata could be loaded.",
            110 => "Source does not contain a valid HFS+ volume header.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapFatStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required metadata could be loaded.",
            70 => "Source does not contain a valid FAT32/exFAT boot sector.",
            71 => "FAT/exFAT scan encountered an invalid cluster chain.",
            72 => "FAT/exFAT scan overflowed internal limits.",
            73 => "FAT/exFAT scan detected a cluster loop.",
            74 => "FAT/exFAT directory entry set is truncated.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static EngineRaidLayoutMetadata MapNativeRaidLayout(NativeRaidLayout nativeLayout)
    {
        var diskOrder = new List<uint>((int)Math.Min(nativeLayout.DiskOrderCount, RaidLayoutMaxMembers));
        var diskOrderCount = (int)Math.Min(nativeLayout.DiskOrderCount, RaidLayoutMaxMembers);
        for (var index = 0; index < diskOrderCount; index++)
        {
            diskOrder.Add(nativeLayout.DiskOrder[index]);
        }

        return new EngineRaidLayoutMetadata(
            MetadataFamily: MapRaidMetadataFamily(nativeLayout.MetadataFamily),
            Level: MapRaidLevel(nativeLayout.Level),
            MemberCount: nativeLayout.MemberCount,
            StripeSizeBytes: nativeLayout.StripeSizeBytes,
            DataOffsetBytes: nativeLayout.DataOffsetBytes,
            ParityRotation: MapRaidParityRotation(nativeLayout.ParityRotation),
            ConfidenceScore: nativeLayout.ConfidenceScore,
            DiskOrder: diskOrder);
    }

    private static string MapRaidStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            31 => "Source read ended before required RAID metadata could be loaded.",
            140 => "No supported RAID metadata detected.",
            141 => "RAID metadata was detected but layout is unsupported or invalid.",
            142 => "Manual RAID override is invalid.",
            44 => "Unable to write virtual RAID assembly output.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapFatFilesystem(uint filesystemKind)
    {
        return filesystemKind switch
        {
            FatFilesystemKindFat32 => "FAT32",
            FatFilesystemKindExFat => "exFAT",
            _ => "Unknown",
        };
    }

    private static string MapExtFilesystem(uint filesystemKind)
    {
        return filesystemKind switch
        {
            ExtFilesystemKindExt2 => "ext2",
            ExtFilesystemKindExt3 => "ext3",
            ExtFilesystemKindExt4 => "ext4",
            _ => "ext",
        };
    }

    private static string MapRaidMetadataFamily(uint family)
    {
        return family switch
        {
            RaidMetadataFamilyLinuxMd => "Linux MD",
            RaidMetadataFamilyWindowsStorageSpaces => "Windows Storage Spaces",
            RaidMetadataFamilyIntelImsm => "Intel IMSM/RST",
            RaidMetadataFamilyDdf => "DDF",
            _ => "Unknown",
        };
    }

    private static uint MapRaidMetadataFamilyCode(string metadataFamily)
    {
        if (string.Equals(metadataFamily, "linux md", StringComparison.OrdinalIgnoreCase))
        {
            return RaidMetadataFamilyLinuxMd;
        }

        if (string.Equals(metadataFamily, "windows storage spaces", StringComparison.OrdinalIgnoreCase)
            || string.Equals(metadataFamily, "storage spaces", StringComparison.OrdinalIgnoreCase))
        {
            return RaidMetadataFamilyWindowsStorageSpaces;
        }

        if (string.Equals(metadataFamily, "intel imsm/rst", StringComparison.OrdinalIgnoreCase)
            || string.Equals(metadataFamily, "intel imsm", StringComparison.OrdinalIgnoreCase)
            || string.Equals(metadataFamily, "intel rst", StringComparison.OrdinalIgnoreCase))
        {
            return RaidMetadataFamilyIntelImsm;
        }

        if (string.Equals(metadataFamily, "ddf", StringComparison.OrdinalIgnoreCase))
        {
            return RaidMetadataFamilyDdf;
        }

        return RaidMetadataFamilyLinuxMd;
    }

    private static string MapRaidLevel(uint level)
    {
        return level switch
        {
            RaidLevelRaid0 => "RAID0",
            RaidLevelRaid1 => "RAID1",
            RaidLevelRaid4 => "RAID4",
            RaidLevelRaid5 => "RAID5",
            RaidLevelRaid6 => "RAID6",
            RaidLevelRaid10 => "RAID10",
            RaidLevelUnknown => "Unknown",
            _ => "Unknown",
        };
    }

    private static uint MapRaidLevelCode(string? level)
    {
        if (string.IsNullOrWhiteSpace(level))
        {
            return RaidLevelUnknown;
        }

        return level.Trim().ToLowerInvariant() switch
        {
            "raid0" => RaidLevelRaid0,
            "raid1" => RaidLevelRaid1,
            "raid4" => RaidLevelRaid4,
            "raid5" => RaidLevelRaid5,
            "raid6" => RaidLevelRaid6,
            "raid10" => RaidLevelRaid10,
            "unknown" => RaidLevelUnknown,
            _ => throw new ArgumentException("Unsupported RAID level override value.", nameof(level)),
        };
    }

    private static string MapRaidParityRotation(uint parityRotation)
    {
        return parityRotation switch
        {
            RaidParityLeftSymmetric => "LeftSymmetric",
            RaidParityRightSymmetric => "RightSymmetric",
            RaidParityUnknown => "Unknown",
            _ => "Unknown",
        };
    }

    private static uint MapRaidParityRotationCode(string? parityRotation)
    {
        if (string.IsNullOrWhiteSpace(parityRotation))
        {
            return RaidParityUnknown;
        }

        return parityRotation.Trim().ToLowerInvariant() switch
        {
            "left" => RaidParityLeftSymmetric,
            "leftsymmetric" => RaidParityLeftSymmetric,
            "right" => RaidParityRightSymmetric,
            "rightsymmetric" => RaidParityRightSymmetric,
            "unknown" => RaidParityUnknown,
            _ => throw new ArgumentException("Unsupported RAID parity rotation override value.", nameof(parityRotation)),
        };
    }

    private static NativeRaidLayout BuildNativeRaidLayout(EngineRaidLayoutMetadata layout)
    {
        var native = new NativeRaidLayout
        {
            MetadataFamily = MapRaidMetadataFamilyCode(layout.MetadataFamily),
            Level = MapRaidLevelCode(layout.Level),
            MemberCount = layout.MemberCount,
            StripeSizeBytes = layout.StripeSizeBytes,
            DataOffsetBytes = layout.DataOffsetBytes,
            ParityRotation = MapRaidParityRotationCode(layout.ParityRotation),
            ConfidenceScore = layout.ConfidenceScore,
            Reserved0 = new byte[3],
            DiskOrderCount = 0,
            DiskOrder = new uint[RaidLayoutMaxMembers],
        };

        if (layout.DiskOrder is { Count: > 0 })
        {
            var diskOrderCount = Math.Min(layout.DiskOrder.Count, RaidLayoutMaxMembers);
            native.DiskOrderCount = (uint)diskOrderCount;
            for (var i = 0; i < diskOrderCount; i++)
            {
                native.DiskOrder[i] = layout.DiskOrder[i];
            }
        }

        return native;
    }

    private static NativeRaidManualOverride? BuildNativeRaidManualOverride(EngineRaidManualOverride? manualOverride)
    {
        if (manualOverride is null)
        {
            return null;
        }

        var native = new NativeRaidManualOverride
        {
            Flags = 0,
            Level = RaidLevelUnknown,
            StripeSizeBytes = 0,
            DataOffsetBytes = 0,
            ParityRotation = RaidParityUnknown,
            DiskOrderCount = 0,
            DiskOrder = new uint[RaidLayoutMaxMembers],
        };

        if (manualOverride.OverrideLevel)
        {
            native.Flags |= RaidManualOverrideFlagLevel;
            native.Level = MapRaidLevelCode(manualOverride.Level);
        }

        if (manualOverride.OverrideStripeSize)
        {
            native.Flags |= RaidManualOverrideFlagStripeSize;
            native.StripeSizeBytes = manualOverride.StripeSizeBytes;
        }

        if (manualOverride.OverrideDataOffset)
        {
            native.Flags |= RaidManualOverrideFlagDataOffset;
            native.DataOffsetBytes = manualOverride.DataOffsetBytes;
        }

        if (manualOverride.OverrideParityRotation)
        {
            native.Flags |= RaidManualOverrideFlagParityRotation;
            native.ParityRotation = MapRaidParityRotationCode(manualOverride.ParityRotation);
        }

        if (manualOverride.DiskOrder is { Count: > 0 })
        {
            native.Flags |= RaidManualOverrideFlagDiskOrder;
            var diskOrderCount = Math.Min(manualOverride.DiskOrder.Count, RaidLayoutMaxMembers);
            native.DiskOrderCount = (uint)diskOrderCount;
            for (var i = 0; i < diskOrderCount; i++)
            {
                native.DiskOrder[i] = manualOverride.DiskOrder[i];
            }
        }

        return native;
    }

    private static string MapCarveStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapVssStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            60 => "VSS snapshot enumeration is unsupported on this platform.",
            61 => "PowerShell is unavailable for VSS snapshot enumeration.",
            62 => "VSS snapshot query failed.",
            63 => "VSS snapshot query output was malformed.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapEncryptedSourceStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            0 => "Encrypted source operation completed.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            171 => "Encrypted source remains locked and requires credentials or key material.",
            173 => "Credential material was rejected for encrypted source unlock.",
            174 => "Encrypted source provider is unsupported in current build.",
            _ => "Unknown engine response.",
        };
    }

    private static string MapEncryptedProvider(uint providerCode)
    {
        return providerCode switch
        {
            EncryptedProviderBitLocker => "bitlocker",
            EncryptedProviderFileVault => "filevault",
            EncryptedProviderLuks => "luks",
            _ => "auto",
        };
    }

    private static string MapConfidenceTier(uint confidenceTierCode)
    {
        return confidenceTierCode switch
        {
            0 => "Very high",
            1 => "High",
            2 => "Medium",
            3 => "Low",
            4 => "Very low",
            _ => "Medium",
        };
    }

    private static string MapEvidenceSources(uint flags)
    {
        var sources = new List<string>(capacity: 5);
        if ((flags & CandidateFlagEvidenceMft) != 0)
        {
            sources.Add("MFT");
        }

        if ((flags & CandidateFlagEvidenceDirectoryIndex) != 0)
        {
            sources.Add("Directory index");
        }

        if ((flags & CandidateFlagEvidenceUsn) != 0)
        {
            sources.Add("USN");
        }

        if ((flags & CandidateFlagEvidenceVss) != 0)
        {
            sources.Add("VSS");
        }

        if ((flags & CandidateFlagEvidenceCarve) != 0)
        {
            sources.Add("Carve");
        }

        if (sources.Count == 0)
        {
            return "MFT";
        }

        return string.Join(", ", sources);
    }

    private static string MapRecoverStatusMessage(int statusCode)
    {
        return statusCode switch
        {
            20 => "Session not found.",
            30 => "Source does not contain a valid NTFS boot sector.",
            31 => "Source read ended before required metadata could be loaded.",
            32 => "NTFS record size is unsupported.",
            33 => "NTFS metadata offset arithmetic overflowed.",
            41 => "Requested candidate record was not found in scanned MFT range.",
            42 => "Candidate record does not expose a recoverable data attribute.",
            43 => "Recovery destination path is invalid.",
            44 => "Failed writing recovered output file.",
            45 => "Compressed NTFS data stream could not be decompressed for export in this mode.",
            46 => "Encrypted NTFS data stream requires decryption keys and is not recoverable in this mode.",
            47 => "No exportable data stream was recovered (default stream unavailable and named streams were skipped).",
            70 => "Source does not contain a valid FAT32/exFAT boot sector.",
            72 => "FAT/exFAT recovery overflowed internal limits.",
            75 => "FAT/exFAT candidate start cluster is invalid.",
            76 => "No bytes were recoverable for the requested FAT/exFAT candidate.",
            91 => "ext recovery is unavailable for this candidate in the current build.",
            170 => "Candidate metadata does not contain a supported byte-mapping layout for full-content export.",
            171 => "Candidate bytes are locked by source encryption and require explicit unlock before recovery.",
            172 => "Candidate payload range could not be read from the source.",
            10 => "Invalid source path.",
            11 => "Unsupported platform.",
            12 => "Access denied.",
            13 => "Source not found.",
            14 => "Windows I/O error.",
            15 => "Invalid read offset.",
            16 => "Misaligned read parameters.",
            _ => "Unknown engine response.",
        };
    }

    private static EngineRecoverCandidateResult BuildRecoverResult(
        int statusCode,
        ulong bytesWritten,
        bool partial,
        uint diagnosticsFlags)
    {
        var diagnosticsSummary = MapRecoveryDiagnostics(diagnosticsFlags, partial);
        if (statusCode == 0)
        {
            return new EngineRecoverCandidateResult(
                true,
                true,
                partial,
                bytesWritten,
                diagnosticsFlags,
                diagnosticsSummary,
                partial ? "Candidate recovered with partial data." : "Candidate recovered successfully.",
                statusCode);
        }

        return new EngineRecoverCandidateResult(
            true,
            false,
            false,
            0,
            diagnosticsFlags,
            diagnosticsSummary,
            MapRecoverStatusMessage(statusCode),
            statusCode);
    }

    private static string MapRecoveryDiagnostics(uint flags, bool partial)
    {
        if (flags == 0 && !partial)
        {
            return "No additional diagnostics.";
        }

        var details = new List<string>();
        if ((flags & RecoveryDiagHasNamedDataStream) != 0)
        {
            details.Add("Named data stream(s) detected");
        }
        if ((flags & RecoveryDiagSkippedNamedDataStreams) != 0)
        {
            details.Add("Named data stream(s) skipped");
        }
        if ((flags & RecoveryDiagExportedNamedDataStreams) != 0)
        {
            details.Add("Named data stream(s) exported as sidecar files");
        }
        if ((flags & RecoveryDiagCompressedAttribute) != 0)
        {
            details.Add("Compressed NTFS attribute present");
        }
        if ((flags & RecoveryDiagSparseAttribute) != 0)
        {
            details.Add("Sparse NTFS attribute present");
        }
        if ((flags & RecoveryDiagEncryptedAttribute) != 0)
        {
            details.Add("Encrypted NTFS attribute present");
        }
        if ((flags & RecoveryDiagUnsupportedCompressed) != 0)
        {
            details.Add("Compressed attribute decompression failed or was skipped");
        }
        if ((flags & RecoveryDiagUnsupportedEncrypted) != 0)
        {
            details.Add("Encrypted attribute exported without decryption");
        }
        if ((flags & RecoveryDiagSparseZeroFilled) != 0)
        {
            details.Add("Sparse ranges zero-filled");
        }
        if ((flags & RecoveryDiagNoDefaultDataStream) != 0)
        {
            details.Add("Default unnamed data stream not found");
        }
        if ((flags & RecoveryDiagUnreadableRange) != 0)
        {
            details.Add("Unreadable source range encountered");
        }
        if ((flags & RecoveryDiagEncryptedLocked) != 0)
        {
            details.Add("Encrypted source remains locked");
        }
        if ((flags & RecoveryDiagUnsupportedLayout) != 0)
        {
            details.Add("Unsupported metadata layout for byte export");
        }
        if (partial)
        {
            details.Add("Recovery marked partial");
        }

        return details.Count == 0 ? "No additional diagnostics." : string.Join("; ", details);
    }

    private static string? DecodeUtf8(byte[]? bytes)
    {
        if (bytes is null || bytes.Length == 0)
        {
            return null;
        }

        var length = Array.IndexOf(bytes, (byte)0);
        if (length < 0)
        {
            length = bytes.Length;
        }

        if (length == 0)
        {
            return null;
        }

        return Encoding.UTF8.GetString(bytes, 0, length);
    }

    private const uint CandidateFlagInUse = 0x0001;
    private const uint CandidateFlagDeleted = 0x0002;
    private const uint CandidateFlagDirectory = 0x0004;
    private const uint CandidateFlagNonResidentData = 0x0008;
    private const uint CandidateFlagHasNamedDataStream = 0x0040;
    private const uint CandidateFlagCompressed = 0x0080;
    private const uint CandidateFlagSparse = 0x0100;
    private const uint CandidateFlagEncrypted = 0x0200;
    private const uint CandidateFlagEvidenceMft = 0x1000;
    private const uint CandidateFlagEvidenceDirectoryIndex = 0x2000;
    private const uint CandidateFlagEvidenceUsn = 0x4000;
    private const uint CandidateFlagEvidenceVss = 0x8000;
    private const uint CandidateFlagEvidenceCarve = 0x0001_0000;
    private const uint CandidateFlagHasFileMetadata = 0x0002_0000;
    private const uint CandidateFlagGhostRecord = 0x0004_0000;
    private const uint RefsDeletedCandidateFlagDeleted = 0x0001;
    private const uint ExtDeletedCandidateFlagDeleted = 0x0001;
    private const uint ExtDeletedCandidateFlagDirectory = 0x0002;
    private const uint XfsDeletedCandidateFlagDeleted = 0x0001;
    private const uint XfsDeletedCandidateFlagDirectory = 0x0002;
    private const uint UfsDeletedCandidateFlagDeleted = 0x0001;
    private const uint UfsDeletedCandidateFlagDirectory = 0x0002;
    private const uint ApfsDeletedCandidateFlagDeleted = 0x0001;
    private const uint ApfsDeletedCandidateFlagDirectory = 0x0002;
    private const uint HfsDeletedCandidateFlagDeleted = 0x0001;
    private const uint HfsDeletedCandidateFlagDirectory = 0x0002;
    private const uint FatDeletedCandidateFlagDeleted = 0x0001;
    private const uint FatDeletedCandidateFlagDirectory = 0x0002;
    private const uint ExtFilesystemKindExt2 = 1;
    private const uint ExtFilesystemKindExt3 = 2;
    private const uint ExtFilesystemKindExt4 = 3;
    private const uint FatFilesystemKindFat32 = 1;
    private const uint FatFilesystemKindExFat = 2;
    private const int RaidLayoutMaxMembers = 32;
    private const uint RaidManualOverrideFlagLevel = 0x0001;
    private const uint RaidManualOverrideFlagStripeSize = 0x0002;
    private const uint RaidManualOverrideFlagDataOffset = 0x0004;
    private const uint RaidManualOverrideFlagParityRotation = 0x0008;
    private const uint RaidManualOverrideFlagDiskOrder = 0x0010;
    private const uint RaidMetadataFamilyLinuxMd = 1;
    private const uint RaidMetadataFamilyWindowsStorageSpaces = 2;
    private const uint RaidMetadataFamilyIntelImsm = 3;
    private const uint RaidMetadataFamilyDdf = 4;
    private const uint RaidLevelRaid0 = 1;
    private const uint RaidLevelRaid1 = 2;
    private const uint RaidLevelRaid4 = 3;
    private const uint RaidLevelRaid5 = 4;
    private const uint RaidLevelRaid6 = 5;
    private const uint RaidLevelRaid10 = 6;
    private const uint RaidLevelUnknown = 255;
    private const uint RaidParityLeftSymmetric = 1;
    private const uint RaidParityRightSymmetric = 2;
    private const uint RaidParityUnknown = 255;
    private const uint CarveCandidateFlagPartial = 0x0001;
    private const uint RecoveryDiagHasNamedDataStream = 0x0001;
    private const uint RecoveryDiagSkippedNamedDataStreams = 0x0002;
    private const uint RecoveryDiagCompressedAttribute = 0x0004;
    private const uint RecoveryDiagSparseAttribute = 0x0008;
    private const uint RecoveryDiagEncryptedAttribute = 0x0010;
    private const uint RecoveryDiagUnsupportedCompressed = 0x0020;
    private const uint RecoveryDiagUnsupportedEncrypted = 0x0040;
    private const uint RecoveryDiagSparseZeroFilled = 0x0080;
    private const uint RecoveryDiagNoDefaultDataStream = 0x0100;
    private const uint RecoveryDiagExportedNamedDataStreams = 0x0200;
    private const uint RecoveryDiagUnreadableRange = 0x0400;
    private const uint RecoveryDiagEncryptedLocked = 0x0800;
    private const uint RecoveryDiagUnsupportedLayout = 0x1000;
    private const uint EncryptedProviderBitLocker = 1;
    private const uint EncryptedProviderFileVault = 2;
    private const uint EncryptedProviderLuks = 3;
    private const uint EncryptedSourceFlagLocked = 0x0001;
    private const uint EncryptedSourceFlagSupportsPassword = 0x0002;
    private const uint EncryptedSourceFlagSupportsRecoveryKey = 0x0004;
    private const uint EncryptedSourceFlagSupportsKeyFile = 0x0008;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeNtfsBootMetadata
    {
        public ushort BytesPerSector;
        public byte SectorsPerCluster;
        public byte Reserved0;
        public uint ClusterSizeBytes;
        public uint FileRecordSizeBytes;
        public uint IndexRecordSizeBytes;
        public ulong MftCluster;
        public ulong MftOffsetBytes;
        public ulong VolumeSizeBytes;
        public ulong VolumeSerial;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRefsBootMetadata
    {
        public ushort BytesPerSector;
        public byte SectorsPerCluster;
        public byte Reserved0;
        public uint ClusterSizeBytes;
        public ulong TotalSectors;
        public ulong VolumeSizeBytes;
        public ulong VolumeSerial;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRefsDeletedCandidate
    {
        public uint Flags;
        public ulong ObjectId;
        public ulong SizeBytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeExtSuperblockMetadata
    {
        public uint FilesystemKind;
        public uint BlockSizeBytes;
        public ushort InodeSizeBytes;
        public ushort Reserved0;
        public uint InodesPerGroup;
        public uint TotalInodes;
        public ulong TotalBlocks;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeExtDeletedCandidate
    {
        public uint Flags;
        public ulong InodeNumber;
        public ulong EntryOffsetBytes;
        public ulong SizeBytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeXfsSuperblockMetadata
    {
        public uint BlockSizeBytes;
        public ushort InodeSizeBytes;
        public ushort Reserved0;
        public uint AgCount;
        public ulong DataBlocks;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeXfsDeletedCandidate
    {
        public uint Flags;
        public ulong InodeNumber;
        public ulong SizeBytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUfsSuperblockMetadata
    {
        public uint Magic;
        public uint BlockSizeBytes;
        public uint FragmentSizeBytes;
        public uint Reserved0;
        public ulong TotalBlocks;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUfsDeletedCandidate
    {
        public uint Flags;
        public uint InodeNumber;
        public uint Reserved0;
        public ulong SizeBytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeApfsContainerMetadata
    {
        public uint BlockSizeBytes;
        public uint Reserved0;
        public ulong BlockCount;
        public ulong Features;
        public ulong IncompatFeatures;
        public ulong ContainerObjectId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeApfsDeletedCandidate
    {
        public uint Flags;
        public uint Reserved0;
        public ulong Cnid;
        public ulong SizeBytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeHfsVolumeMetadata
    {
        public ushort Signature;
        public ushort Version;
        public uint BlockSizeBytes;
        public uint TotalBlocks;
        public uint FileCount;
        public uint FolderCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeHfsDeletedCandidate
    {
        public uint Flags;
        public uint Cnid;
        public ulong SizeBytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFatBootMetadata
    {
        public uint FilesystemKind;
        public ushort BytesPerSector;
        public byte SectorsPerCluster;
        public byte FatCount;
        public uint ClusterSizeBytes;
        public ulong TotalSectors;
        public uint RootDirFirstCluster;
        public uint Reserved0;
        public ulong FatOffsetBytes;
        public ulong DataRegionOffsetBytes;
        public uint VolumeSerial;
        public uint Reserved1;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRaidLayout
    {
        public uint MetadataFamily;
        public uint Level;
        public uint MemberCount;
        public uint StripeSizeBytes;
        public ulong DataOffsetBytes;
        public uint ParityRotation;
        public byte ConfidenceScore;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved0;

        public uint DiskOrderCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = RaidLayoutMaxMembers)]
        public uint[] DiskOrder;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRaidManualOverride
    {
        public uint Flags;
        public uint Level;
        public uint StripeSizeBytes;
        public ulong DataOffsetBytes;
        public uint ParityRotation;
        public uint DiskOrderCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = RaidLayoutMaxMembers)]
        public uint[] DiskOrder;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRaidLogicalMapping
    {
        public uint MemberIndex;
        public ulong MemberOffsetBytes;
        public uint HasParityMember;
        public uint ParityMemberIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRaidDegradedAssessment
    {
        public uint MissingMemberCount;
        public uint SampleCount;
        public uint RecoverableSampleCount;
        public byte RecoverabilityPercent;
        public byte ConfidencePenalty;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public byte[] Reserved0;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
        public byte[] Recommendation;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeNtfsQuickScanSummary
    {
        public uint ParsedRecords;
        public uint ParseFailures;
        public uint ResidentAttributeCount;
        public uint NonResidentAttributeCount;
        public uint DeletedRecords;
        public uint DirectoryRecords;
        public uint NamedRecords;
        public uint RecordsWithNonResidentData;
        public uint UsnEnrichedRecords;
        public uint UsnGhostRecords;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeNtfsQuickScanCandidate
    {
        public uint RecordNumber;
        public uint Flags;
        public ulong ParentRecordNumber;
        public uint ConfidenceTier;
        public uint Reserved0;
        public ulong DataSizeBytes;
        public ulong AllocatedSizeBytes;
        public uint FileAttributes;
        public uint Reserved1;
        public ulong CreatedFileTimeUtc;
        public ulong ModifiedFileTimeUtc;
        public ulong MftModifiedFileTimeUtc;
        public ulong AccessedFileTimeUtc;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ConfidenceReason;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFatDeletedCandidate
    {
        public uint Flags;
        public uint StartCluster;
        public ulong SizeBytes;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] Name;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ReconstructedPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCarveCandidate
    {
        public ulong OffsetBytes;
        public ulong LengthBytes;
        public uint Flags;
        public uint ConfidenceTier;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Format;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] SuggestedName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] ConfidenceReason;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCarveSignaturePackMetadata
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] PackName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] PackVersion;

        public uint FormatCount;
        public uint FamilyFlags;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
        public byte[] FormatsCsv;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeVssSnapshot
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] SnapshotId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)]
        public byte[] VolumeName;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)]
        public byte[] DeviceObject;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] InstallTimeUtc;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 260)]
        public byte[] SnapshotPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeEncryptedSourceInfo
    {
        public uint ProviderCode;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Identifier;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 160)]
        public byte[] DisplayName;
    }

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr fr_engine_version();

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_carve_signature_pack_metadata(
        out NativeCarveSignaturePackMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_health_check();

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_source_readonly(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sourcePath,
        int sourceKind,
        out ulong sizeBytes);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_open_source_session_readonly(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sourcePath,
        int sourceKind,
        out ulong sessionId,
        out ulong sizeBytes);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_read_source_session(
        ulong sessionId,
        ulong offset,
        byte[] buffer,
        uint bufferLength,
        out uint bytesRead);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_source_session_alignment(
        ulong sessionId,
        out uint alignmentBytes);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_ntfs_boot_from_session(
        ulong sessionId,
        out NativeNtfsBootMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_refs_boot_from_session(
        ulong sessionId,
        out NativeRefsBootMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_refs_deleted_candidates_from_session(
        ulong sessionId,
        uint maxEntries,
        [Out] NativeRefsDeletedCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_ext_superblock_from_session(
        ulong sessionId,
        out NativeExtSuperblockMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_ext_deleted_candidates_from_session(
        ulong sessionId,
        uint maxEntries,
        [Out] NativeExtDeletedCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_xfs_superblock_from_session(
        ulong sessionId,
        out NativeXfsSuperblockMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_xfs_deleted_candidates_from_session(
        ulong sessionId,
        uint maxEntries,
        [Out] NativeXfsDeletedCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_ufs_superblock_from_session(
        ulong sessionId,
        out NativeUfsSuperblockMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_ufs_deleted_candidates_from_session(
        ulong sessionId,
        uint maxEntries,
        [Out] NativeUfsDeletedCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_apfs_container_from_session(
        ulong sessionId,
        out NativeApfsContainerMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_apfs_deleted_candidates_from_session(
        ulong sessionId,
        uint maxEntries,
        [Out] NativeApfsDeletedCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_hfs_volume_header_from_session(
        ulong sessionId,
        out NativeHfsVolumeMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_hfs_deleted_candidates_from_session(
        ulong sessionId,
        uint maxEntries,
        [Out] NativeHfsDeletedCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_fat_boot_from_session(
        ulong sessionId,
        out NativeFatBootMetadata metadata);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_fat_deleted_candidates_from_session(
        ulong sessionId,
        uint maxEntries,
        [Out] NativeFatDeletedCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_raid_layout_from_session(
        ulong sessionId,
        IntPtr overrideConfig,
        out NativeRaidLayout layout);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_raid_layout_from_session(
        ulong sessionId,
        ref NativeRaidManualOverride overrideConfig,
        out NativeRaidLayout layout);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_open_virtual_raid_session(
        [In] ulong[] memberSessionIds,
        uint memberCount,
        IntPtr overrideConfig,
        out ulong virtualSessionId,
        out ulong sizeBytes,
        out NativeRaidLayout layout);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_open_virtual_raid_session(
        [In] ulong[] memberSessionIds,
        uint memberCount,
        ref NativeRaidManualOverride overrideConfig,
        out ulong virtualSessionId,
        out ulong sizeBytes,
        out NativeRaidLayout layout);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_probe_virtual_raid_session(
        ulong virtualSessionId,
        out NativeRaidLayout layout);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_close_virtual_raid_session(
        ulong virtualSessionId);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_map_raid_logical_offset(
        ref NativeRaidLayout layout,
        ulong logicalOffsetBytes,
        out NativeRaidLogicalMapping mapping);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_assess_raid_degraded_layout(
        ref NativeRaidLayout layout,
        [In] uint[] missingMembers,
        uint missingMemberCount,
        uint sampleCount,
        out NativeRaidDegradedAssessment assessment);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_quick_scan_ntfs_from_session(
        ulong sessionId,
        uint maxRecords,
        out NativeNtfsQuickScanSummary summary);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_ntfs_quick_scan_candidates_from_session(
        ulong sessionId,
        uint maxRecords,
        [Out] NativeNtfsQuickScanCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_ntfs_quick_scan_candidates_from_session_with_usn(
        ulong sessionId,
        uint maxRecords,
        [Out] NativeNtfsQuickScanCandidate[] candidates,
        uint candidateCapacity,
        out uint written,
        [In] byte[] usnJournalBytes,
        uint usnJournalLength);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_carve_candidates_from_session(
        ulong sessionId,
        uint familyFlags,
        ulong maxScanBytes,
        [Out] NativeCarveCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_get_carve_candidates_from_session_window(
        ulong sessionId,
        uint familyFlags,
        ulong windowOffsetBytes,
        ulong windowLengthBytes,
        [Out] NativeCarveCandidate[] candidates,
        uint candidateCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_list_vss_snapshots(
        [Out] NativeVssSnapshot[] snapshots,
        uint snapshotCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_list_encrypted_sources(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sourcePath,
        int sourceKind,
        [Out] NativeEncryptedSourceInfo[] sources,
        uint sourceCapacity,
        out uint written);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_unlock_encrypted_source(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sourcePath,
        int sourceKind,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string provider,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string credentialKind,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string credentialMaterial,
        out int unlocked);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_lock_encrypted_source(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sourcePath,
        int sourceKind,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string provider,
        out int locked);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_ntfs_candidate_to_file(
        ulong sessionId,
        uint recordNumber,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_ntfs_candidate_to_file_ex(
        ulong sessionId,
        uint recordNumber,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial,
        out uint diagnosticsFlags);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_fat_candidate_to_file(
        ulong sessionId,
        uint startCluster,
        ulong sizeBytes,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_ext_candidate_to_file(
        ulong sessionId,
        ulong inodeNumber,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_refs_candidate_to_file(
        ulong sessionId,
        ulong objectId,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_apfs_candidate_to_file(
        ulong sessionId,
        ulong cnid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_hfs_candidate_to_file(
        ulong sessionId,
        uint cnid,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_xfs_candidate_to_file(
        ulong sessionId,
        ulong inodeNumber,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_recover_ufs_candidate_to_file(
        ulong sessionId,
        uint inodeNumber,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string outputPath,
        out ulong bytesWritten,
        out int partial);

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern int fr_close_source_session(ulong sessionId);
}
