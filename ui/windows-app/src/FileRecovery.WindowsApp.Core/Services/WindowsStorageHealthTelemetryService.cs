using FileRecovery.WindowsApp.Core.Models;
using System.Management;
using System.Text.RegularExpressions;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class WindowsStorageHealthTelemetryService : IStorageHealthTelemetryService
{
    public Task<StorageHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        return Task.Run(() =>
        {
            var warnings = new List<string>();
            var predictFailureByDisk = new Dictionary<int, bool>();

            try
            {
                var scope = new ManagementScope(@"\\.\root\wmi");
                scope.Connect();
                using var statusSearcher = new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery("SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus"));
                using var statusRows = statusSearcher.Get();
                foreach (ManagementObject row in statusRows)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var instanceName = row["InstanceName"]?.ToString();
                    if (string.IsNullOrWhiteSpace(instanceName))
                    {
                        continue;
                    }

                    var index = TryExtractDiskIndex(instanceName);
                    if (!index.HasValue)
                    {
                        continue;
                    }

                    var predictFailure = Convert.ToBoolean(row["PredictFailure"] ?? false);
                    predictFailureByDisk[index.Value] = predictFailure;
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"SMART predict-failure probe unavailable: {ex.Message}");
            }

            var records = new List<StorageDeviceHealthRecord>();
            try
            {
                using var diskSearcher = new ManagementObjectSearcher(
                    "SELECT DeviceID, Index, Model, Status FROM Win32_DiskDrive");
                using var disks = diskSearcher.Get();
                foreach (ManagementObject disk in disks)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var deviceId = disk["DeviceID"]?.ToString() ?? "(unknown)";
                    var model = disk["Model"]?.ToString()?.Trim() ?? "Unknown model";
                    var rawStatus = disk["Status"]?.ToString()?.Trim();
                    var diskIndex = TryParseNullableInt32(disk["Index"]);
                    var predictFailure = diskIndex.HasValue
                        && predictFailureByDisk.TryGetValue(diskIndex.Value, out var mappedFailure)
                        && mappedFailure;

                    var health = EvaluateHealth(rawStatus, predictFailure);
                    var warning = health is "Predicted Failure" or "Degraded"
                        ? $"Disk {diskIndex?.ToString() ?? "?"} reports {health}."
                        : null;
                    records.Add(new StorageDeviceHealthRecord(
                        DiskIndex: diskIndex,
                        DeviceId: deviceId,
                        Model: model,
                        HealthStatus: health,
                        PredictFailure: predictFailure,
                        RawStatus: rawStatus,
                        Warning: warning));
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Disk health enumeration failed: {ex.Message}");
            }

            if (records.Count == 0)
            {
                warnings.Add("No physical disk health telemetry records were available.");
            }

            return new StorageHealthSnapshot(records, warnings);
        }, cancellationToken);
    }

    private static int? TryExtractDiskIndex(string instanceName)
    {
        var match = Regex.Match(instanceName, @"PHYSICALDRIVE(?<index>\d+)", RegexOptions.IgnoreCase);
        if (!match.Success)
        {
            return null;
        }

        return int.TryParse(match.Groups["index"].Value, out var parsed)
            ? parsed
            : null;
    }

    private static int? TryParseNullableInt32(object? value)
    {
        if (value is null)
        {
            return null;
        }

        return int.TryParse(value.ToString(), out var parsed)
            ? parsed
            : null;
    }

    private static string EvaluateHealth(string? rawStatus, bool predictFailure)
    {
        if (predictFailure)
        {
            return "Predicted Failure";
        }

        if (string.IsNullOrWhiteSpace(rawStatus))
        {
            return "Unknown";
        }

        if (string.Equals(rawStatus, "OK", StringComparison.OrdinalIgnoreCase))
        {
            return "Healthy";
        }

        return "Degraded";
    }
}
