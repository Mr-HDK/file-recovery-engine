using FileRecovery.WindowsApp.Core.Models;
using System.IO;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class WinPeRuntimeService : IWinPeRuntimeService
{
    private readonly IWinPeRuntimeProbe _probe;

    public WinPeRuntimeService(IWinPeRuntimeProbe probe)
    {
        _probe = probe;
    }

    public RuntimeEnvironmentProfile GetRuntimeProfile()
    {
        var bootDrive = NormalizeDrive(_probe.GetEnvironmentVariable("SystemDrive")) ?? "C:";
        var miniNtDetected = _probe.MiniNtRegistryKeyExists();
        var overrideDetected = string.Equals(
            _probe.GetEnvironmentVariable("FR_WINPE_MODE"),
            "1",
            StringComparison.OrdinalIgnoreCase);
        var bootDriveLooksLikeWinPe = string.Equals(bootDrive, "X:", StringComparison.OrdinalIgnoreCase);
        var isWinPe = miniNtDetected || overrideDetected || bootDriveLooksLikeWinPe;
        var mode = isWinPe
            ? RuntimeEnvironmentMode.WinPe
            : RuntimeEnvironmentMode.StandardWindows;

        return new RuntimeEnvironmentProfile(
            Mode: mode,
            BootDrive: bootDrive,
            MiniNtRegistryDetected: miniNtDetected,
            WinPeOverrideDetected: overrideDetected,
            BootDriveLooksLikeWinPe: bootDriveLooksLikeWinPe);
    }

    public OfflineStorageReadinessReport BuildOfflineStorageReadiness(
        IEnumerable<SourceCandidate> sources,
        string? destinationPath)
    {
        var issues = new List<string>();
        var warnings = new List<string>();
        var sourceList = sources?.ToList() ?? [];

        var requiredDrivers = new[] { "disk.sys", "partmgr.sys", "storport.sys" };
        var missingDrivers = requiredDrivers
            .Where(driver => !_probe.CriticalStorageDriverExists(driver))
            .ToArray();
        var criticalDriversDetected = missingDrivers.Length == 0;
        if (!criticalDriversDetected)
        {
            issues.Add($"Critical storage drivers missing: {string.Join(", ", missingDrivers)}.");
        }

        var visibleVolumes = _probe
            .GetVisibleVolumes()
            .Where(volume => volume.IsReady)
            .ToArray();
        var visibleDestinationVolumeCount = visibleVolumes.Count(volume =>
            volume.DriveType is DriveType.Fixed or DriveType.Removable);

        if (visibleDestinationVolumeCount == 0)
        {
            issues.Add("No writable fixed/removable destination volumes detected.");
        }

        var visibleSourceCount = sourceList.Count(source =>
            !string.IsNullOrWhiteSpace(source.DevicePath)
            || !string.IsNullOrWhiteSpace(source.SourcePath));
        if (visibleSourceCount == 0)
        {
            issues.Add("No readable source devices/images detected.");
        }

        var destinationRoot = NormalizeRoot(destinationPath);
        if (!string.IsNullOrWhiteSpace(destinationRoot))
        {
            var destinationVisible = visibleVolumes.Any(volume =>
                string.Equals(
                    NormalizeRoot(volume.RootPath),
                    destinationRoot,
                    StringComparison.OrdinalIgnoreCase));
            if (!destinationVisible)
            {
                issues.Add($"Selected destination root {destinationRoot} is not currently visible.");
            }
        }
        else
        {
            warnings.Add("Destination path not set yet for offline readiness validation.");
        }

        return new OfflineStorageReadinessReport(
            IsReady: issues.Count == 0,
            CriticalStorageDriversDetected: criticalDriversDetected,
            VisibleSourceCount: visibleSourceCount,
            VisibleDestinationVolumeCount: visibleDestinationVolumeCount,
            Issues: issues,
            Warnings: warnings);
    }

    private static string? NormalizeDrive(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = value.Trim();
        if (trimmed.Length == 1 && char.IsLetter(trimmed[0]))
        {
            return $"{char.ToUpperInvariant(trimmed[0])}:";
        }

        if (trimmed.Length >= 2 && char.IsLetter(trimmed[0]) && trimmed[1] == ':')
        {
            return $"{char.ToUpperInvariant(trimmed[0])}:";
        }

        return trimmed.TrimEnd('\\');
    }

    private static string? NormalizeRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            var fullPath = Path.GetFullPath(path);
            var root = Path.GetPathRoot(fullPath);
            if (string.IsNullOrWhiteSpace(root))
            {
                return null;
            }

            return root.TrimEnd('\\').ToUpperInvariant();
        }
        catch
        {
            return null;
        }
    }
}
