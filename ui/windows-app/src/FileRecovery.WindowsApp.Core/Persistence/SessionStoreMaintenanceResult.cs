namespace FileRecovery.WindowsApp.Core.Persistence;

public sealed record SessionStoreMaintenanceResult(
    int DeletedByAge,
    int DeletedByOverflow,
    int RemainingSessions,
    bool Compacted);
