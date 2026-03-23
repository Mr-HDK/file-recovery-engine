namespace FileRecovery.WindowsApp.Core.Models;

public sealed class ValidationResult
{
    public ValidationResult(IReadOnlyList<ValidationIssue> issues)
    {
        Issues = issues;
    }

    public IReadOnlyList<ValidationIssue> Issues { get; }

    public bool IsValid => Issues.All(i => i.Severity != ValidationSeverity.Error);
}
