namespace FileRecovery.WindowsApp.Core.Models;

public sealed record NetworkSourceRequest(
    NetworkSourceProtocol Protocol,
    string SourcePath,
    string? EndpointHint = null
);
