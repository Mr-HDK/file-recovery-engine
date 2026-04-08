namespace FileRecovery.WindowsApp.Core.Models;

public sealed record ImageAcquisitionRequest(
    string SourcePath,
    string DestinationImagePath,
    string? StateLogPath = null,
    int ChunkSizeBytes = 4 * 1024 * 1024,
    bool AllowResume = true,
    ImageReadErrorPolicy ReadErrorPolicy = ImageReadErrorPolicy.ContinueWithZeroFill,
    int MaxReadErrorChunks = 1024
);
