namespace FileRecovery.WindowsApp.Core.Models;

public sealed record SessionRecord(
    Guid SessionId,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    string SourceId,
    string SourceClass,
    string? SignaturePackSet,
    string? CustodyHashChainRef,
    RecoverySourceKind SourceKind,
    string DestinationPath,
    ScanMode ScanMode,
    string Status,
    string? Notes
);
