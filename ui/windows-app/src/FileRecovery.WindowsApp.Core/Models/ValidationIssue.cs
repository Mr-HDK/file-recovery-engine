namespace FileRecovery.WindowsApp.Core.Models;

public enum ValidationSeverity
{
    Info = 0,
    Warning = 1,
    Error = 2,
}

public sealed record ValidationIssue(ValidationSeverity Severity, string Code, string Message);
