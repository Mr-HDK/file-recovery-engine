namespace FileRecovery.WindowsApp.Core.Models;

public enum RecoveryCandidateStatus
{
    Full = 0,
    Partial = 1,
    Invalid = 2,
    OverwrittenRisk = 3,
}

public static class RecoveryCandidateStatusExtensions
{
    public static string ToStorageCode(this RecoveryCandidateStatus status)
    {
        return status switch
        {
            RecoveryCandidateStatus.Full => "full",
            RecoveryCandidateStatus.Partial => "partial",
            RecoveryCandidateStatus.Invalid => "invalid",
            RecoveryCandidateStatus.OverwrittenRisk => "overwritten-risk",
            _ => "partial",
        };
    }

    public static RecoveryCandidateStatus FromStorageCode(string? value)
    {
        return value?.Trim().ToLowerInvariant() switch
        {
            "full" => RecoveryCandidateStatus.Full,
            "partial" => RecoveryCandidateStatus.Partial,
            "invalid" => RecoveryCandidateStatus.Invalid,
            "overwritten-risk" => RecoveryCandidateStatus.OverwrittenRisk,
            _ => RecoveryCandidateStatus.Partial,
        };
    }
}
