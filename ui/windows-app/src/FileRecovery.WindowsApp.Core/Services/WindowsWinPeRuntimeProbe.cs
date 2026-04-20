using FileRecovery.WindowsApp.Core.Models;
using Microsoft.Win32;
using System.IO;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class WindowsWinPeRuntimeProbe : IWinPeRuntimeProbe
{
    private static readonly string[] CriticalDriverPaths =
    [
        Path.Combine("System32", "drivers", "disk.sys"),
        Path.Combine("System32", "drivers", "partmgr.sys"),
        Path.Combine("System32", "drivers", "storport.sys"),
    ];

    public string? GetEnvironmentVariable(string name)
    {
        return Environment.GetEnvironmentVariable(name);
    }

    public bool MiniNtRegistryKeyExists()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\MiniNT");
            return key is not null;
        }
        catch
        {
            return false;
        }
    }

    public bool CriticalStorageDriverExists(string driverFileName)
    {
        if (string.IsNullOrWhiteSpace(driverFileName))
        {
            return false;
        }

        var windowsDirectory = GetEnvironmentVariable("WINDIR");
        if (string.IsNullOrWhiteSpace(windowsDirectory))
        {
            windowsDirectory = @"X:\Windows";
        }

        var expectedPath = Path.Combine(windowsDirectory, "System32", "drivers", driverFileName.Trim());
        if (File.Exists(expectedPath))
        {
            return true;
        }

        foreach (var relativePath in CriticalDriverPaths)
        {
            if (!relativePath.EndsWith(driverFileName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var fallbackPath = Path.Combine(@"X:\Windows", relativePath);
            if (File.Exists(fallbackPath))
            {
                return true;
            }
        }

        return false;
    }

    public IReadOnlyList<VisibleVolume> GetVisibleVolumes()
    {
        try
        {
            return DriveInfo
                .GetDrives()
                .Select(drive => new VisibleVolume(
                    RootPath: drive.RootDirectory.FullName,
                    IsReady: SafeIsReady(drive),
                    DriveType: SafeDriveType(drive)))
                .ToArray();
        }
        catch
        {
            return [];
        }
    }

    private static bool SafeIsReady(DriveInfo drive)
    {
        try
        {
            return drive.IsReady;
        }
        catch
        {
            return false;
        }
    }

    private static DriveType SafeDriveType(DriveInfo drive)
    {
        try
        {
            return drive.DriveType;
        }
        catch
        {
            return DriveType.Unknown;
        }
    }
}
