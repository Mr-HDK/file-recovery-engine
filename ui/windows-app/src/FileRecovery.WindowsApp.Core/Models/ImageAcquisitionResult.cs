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
    long ZeroFilledBytes
);
