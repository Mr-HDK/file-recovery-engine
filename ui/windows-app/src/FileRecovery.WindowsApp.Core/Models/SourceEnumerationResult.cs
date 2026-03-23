namespace FileRecovery.WindowsApp.Core.Models;

public sealed record SourceEnumerationResult(
    IReadOnlyList<SourceCandidate> Sources,
    IReadOnlyList<string> Warnings
);
