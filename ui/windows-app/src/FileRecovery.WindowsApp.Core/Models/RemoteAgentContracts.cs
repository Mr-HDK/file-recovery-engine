namespace FileRecovery.WindowsApp.Core.Models;

public enum RemoteAgentOperationKind
{
    Acquisition = 0,
    Scan = 1,
    Checkpoint = 2,
}

public sealed record RemoteAgentIntegrityMetadata(
    string RequestHashHex,
    string? PayloadHashHex,
    string? CheckpointHashHex);

public sealed record RemoteAgentSessionMetadata(
    string SessionId,
    string KeyId,
    string Nonce,
    DateTimeOffset ExpiresUtc,
    string? RequestSignatureHex,
    string? ResponseSignatureHex);

public sealed record RemoteAgentRequest(
    Guid RequestId,
    string Endpoint,
    RemoteAgentOperationKind Operation,
    DateTimeOffset RequestedUtc,
    RemoteAgentIntegrityMetadata Integrity,
    RemoteAgentSessionMetadata? Session = null);

public sealed record RemoteAgentResponse(
    Guid RequestId,
    RemoteExecutionStatus Status,
    RemoteExecutionErrorCode ErrorCode,
    string Message,
    DateTimeOffset RespondedUtc,
    RemoteAgentIntegrityMetadata Integrity,
    RemoteAgentSessionMetadata? Session = null);
