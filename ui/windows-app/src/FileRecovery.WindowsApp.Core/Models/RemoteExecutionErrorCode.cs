namespace FileRecovery.WindowsApp.Core.Models;

public enum RemoteExecutionErrorCode
{
    None = 0,
    EndpointRequired = 1,
    EndpointUnreachable = 2,
    InvalidResponse = 3,
    IntegrityVerificationFailed = 4,
    OperationRejected = 5,
}
