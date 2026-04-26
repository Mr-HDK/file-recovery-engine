namespace FileRecovery.WindowsApp.Core.Models;

public sealed record StorageDeviceHealthRecord(
    int? DiskIndex,
    string DeviceId,
    string Model,
    string HealthStatus,
    bool PredictFailure,
    string? RawStatus,
    string? Warning);

public sealed record StorageHealthSnapshot(
    IReadOnlyList<StorageDeviceHealthRecord> Devices,
    IReadOnlyList<string> Warnings);
