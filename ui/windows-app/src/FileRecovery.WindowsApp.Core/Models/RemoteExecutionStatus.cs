namespace FileRecovery.WindowsApp.Core.Models;

public enum RemoteExecutionStatus
{
    NotRequested = 0,
    Succeeded = 1,
    Failed = 2,
    InvalidRequest = 3,
    IntegrityFailure = 4,
    Unavailable = 5,
    Canceled = 6,
}
