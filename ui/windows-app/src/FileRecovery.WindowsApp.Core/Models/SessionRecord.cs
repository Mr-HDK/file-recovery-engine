namespace FileRecovery.WindowsApp.Core.Models;

public sealed record SessionRecord(
    Guid SessionId,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    string SourceId,
    RecoverySourceKind SourceKind,
    string DestinationPath,
    ScanMode ScanMode,
    string Status,
    string? Notes
);
