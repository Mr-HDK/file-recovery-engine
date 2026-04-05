namespace FileRecovery.WindowsApp.Core.Models;

public sealed record ImageAcquisitionProgress(
    long BytesWritten,
    long TotalBytes,
    double PercentComplete,
    double ThroughputBytesPerSecond,
    bool Resumed
);
