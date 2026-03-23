namespace FileRecovery.WindowsApp.Core.Models;

public sealed record SourceCandidate(
    string Id,
    RecoverySourceKind Kind,
    string DisplayName,
    string? DevicePath,
    string? FileSystem,
    long? SizeBytes,
    int? SectorSizeBytes,
    int? DiskIndex,
    string? VolumeIdentity,
    string? SourcePath,
    bool ReadOnlyEnforced,
    string? VolumeLabel = null,
    string? MountedPaths = null,
    string? PartitionInfo = null
);
