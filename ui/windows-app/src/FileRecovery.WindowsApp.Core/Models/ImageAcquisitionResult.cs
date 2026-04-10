namespace FileRecovery.WindowsApp.Core.Models;

public sealed record ImageAcquisitionResult(
    string SourcePath,
    string DestinationImagePath,
    string StateLogPath,
    long BytesWritten,
    string SourceSha256Hex,
    string DestinationSha256Hex,
    bool Resumed,
    ImageReadErrorPolicy ReadErrorPolicy,
    int ReadErrorChunks,
    long ZeroFilledBytes,
    bool SourceIsNetwork,
    bool ConstrainedNetworkIo,
    long? MaxNetworkThroughputBytesPerSecond,
    RemoteAgentMode RemoteAgentMode,
    string? RemoteAgentEndpoint,
    string? ChainOfCustodyLogPath,
    int NetworkCheckpointCount
);
