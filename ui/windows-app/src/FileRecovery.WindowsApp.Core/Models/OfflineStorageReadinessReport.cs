namespace FileRecovery.WindowsApp.Core.Models;

public sealed record OfflineStorageReadinessReport(
    bool IsReady,
    bool CriticalStorageDriversDetected,
    int VisibleSourceCount,
    int VisibleDestinationVolumeCount,
    IReadOnlyList<string> Issues,
    IReadOnlyList<string> Warnings
);
