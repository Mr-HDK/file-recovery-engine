using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Services;
using System.IO;

namespace FileRecovery.WindowsApp.Tests;

public sealed class WinPeRuntimeServiceTests
{
    [Fact]
    public void GetRuntimeProfileDetectsWinPeWhenMiniNtRegistryIsPresent()
    {
        var probe = new FakeWinPeRuntimeProbe
        {
            MiniNtRegistryExists = true,
            EnvironmentVariables = { ["SystemDrive"] = "C:" },
        };
        var service = new WinPeRuntimeService(probe);

        var profile = service.GetRuntimeProfile();

        Assert.True(profile.IsWinPe);
        Assert.Equal(RuntimeEnvironmentMode.WinPe, profile.Mode);
        Assert.True(profile.MiniNtRegistryDetected);
        Assert.Equal("C:", profile.BootDrive);
    }

    [Fact]
    public void GetRuntimeProfileDetectsWinPeWhenBootDriveIsX()
    {
        var probe = new FakeWinPeRuntimeProbe
        {
            EnvironmentVariables = { ["SystemDrive"] = "X:" },
        };
        var service = new WinPeRuntimeService(probe);

        var profile = service.GetRuntimeProfile();

        Assert.True(profile.IsWinPe);
        Assert.True(profile.BootDriveLooksLikeWinPe);
        Assert.Equal("X:", profile.BootDrive);
    }

    [Fact]
    public void BuildOfflineStorageReadinessReportsIssuesForMissingDriversAndNoSources()
    {
        var probe = new FakeWinPeRuntimeProbe
        {
            EnvironmentVariables = { ["SystemDrive"] = "X:" },
            Volumes =
            [
                new VisibleVolume("X:\\", IsReady: true, DriveType.Fixed),
            ],
        };
        var service = new WinPeRuntimeService(probe);

        var readiness = service.BuildOfflineStorageReadiness(
            sources: [],
            destinationPath: @"R:\Recovered");

        Assert.False(readiness.IsReady);
        Assert.False(readiness.CriticalStorageDriversDetected);
        Assert.Equal(0, readiness.VisibleSourceCount);
        Assert.Equal(1, readiness.VisibleDestinationVolumeCount);
        Assert.Contains(readiness.Issues, issue => issue.Contains("Critical storage drivers missing", StringComparison.Ordinal));
        Assert.Contains(readiness.Issues, issue => issue.Contains("No readable source devices/images", StringComparison.Ordinal));
        Assert.Contains(readiness.Issues, issue => issue.Contains("Selected destination root", StringComparison.Ordinal));
    }

    [Fact]
    public void BuildOfflineStorageReadinessPassesWhenDriversSourcesAndDestinationAreVisible()
    {
        var probe = new FakeWinPeRuntimeProbe
        {
            EnvironmentVariables = { ["SystemDrive"] = "X:" },
            Volumes =
            [
                new VisibleVolume("X:\\", IsReady: true, DriveType.Fixed),
                new VisibleVolume("R:\\", IsReady: true, DriveType.Removable),
            ],
        };
        probe.Drivers.Add("disk.sys");
        probe.Drivers.Add("partmgr.sys");
        probe.Drivers.Add("storport.sys");

        var sources = new[]
        {
            new SourceCandidate(
                Id: "disk0",
                Kind: RecoverySourceKind.PhysicalDisk,
                DisplayName: "Disk 0",
                DevicePath: @"\\.\PhysicalDrive0",
                FileSystem: null,
                SizeBytes: null,
                SectorSizeBytes: null,
                DiskIndex: 0,
                VolumeIdentity: null,
                SourcePath: null,
                ReadOnlyEnforced: true),
        };

        var service = new WinPeRuntimeService(probe);
        var readiness = service.BuildOfflineStorageReadiness(sources, @"R:\Recovered");

        Assert.True(readiness.IsReady);
        Assert.True(readiness.CriticalStorageDriversDetected);
        Assert.Equal(1, readiness.VisibleSourceCount);
        Assert.Equal(2, readiness.VisibleDestinationVolumeCount);
        Assert.Empty(readiness.Issues);
    }

    private sealed class FakeWinPeRuntimeProbe : IWinPeRuntimeProbe
    {
        public Dictionary<string, string?> EnvironmentVariables { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Drivers { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<VisibleVolume> Volumes { get; set; } = [];
        public bool MiniNtRegistryExists { get; set; }

        public string? GetEnvironmentVariable(string name)
        {
            return EnvironmentVariables.TryGetValue(name, out var value)
                ? value
                : null;
        }

        public bool MiniNtRegistryKeyExists()
        {
            return MiniNtRegistryExists;
        }

        public bool CriticalStorageDriverExists(string driverFileName)
        {
            return Drivers.Contains(driverFileName);
        }

        public IReadOnlyList<VisibleVolume> GetVisibleVolumes()
        {
            return Volumes;
        }
    }
}
