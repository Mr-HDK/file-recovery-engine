namespace FileRecovery.WindowsApp.Core.Models;

public sealed record ImageAcquisitionRequest(
    string SourcePath,
    string DestinationImagePath,
    string? StateLogPath = null,
    int ChunkSizeBytes = 4 * 1024 * 1024,
    bool AllowResume = true,
    ImageReadErrorPolicy ReadErrorPolicy = ImageReadErrorPolicy.ContinueWithZeroFill,
    int MaxReadErrorChunks = 1024,
    bool SourceIsNetwork = false,
    bool EnableConstrainedNetworkIo = false,
    int ConstrainedNetworkChunkSizeBytes = 512 * 1024,
    long? MaxNetworkThroughputBytesPerSecond = null,
    RemoteAgentMode RemoteAgentMode = RemoteAgentMode.Disabled,
    string? RemoteAgentEndpoint = null,
    string? ChainOfCustodyLogPath = null
);
