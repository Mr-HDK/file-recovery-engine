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

public static class NativeEngineProbe
{
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

    [DllImport("file_recovery_engine", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr fr_engine_version();

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
    private static extern int fr_list_vss_snapshots(
        [Out] NativeVssSnapshot[] snapshots,
        uint snapshotCapacity,
        out uint written);

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
    private static extern int fr_close_source_session(ulong sessionId);
}
