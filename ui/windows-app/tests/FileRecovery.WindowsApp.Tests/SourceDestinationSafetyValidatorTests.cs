using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Services;

namespace FileRecovery.WindowsApp.Tests;

public sealed class SourceDestinationSafetyValidatorTests
{
    [Fact]
    public void RejectsSameVolumeForVolumeSource()
    {
        var destination = CreateTemporaryDirectory();
        var topology = new FakeStorageTopologyService();
        topology.Map(destination, "VOL-A", 2);

        var source = new SourceCandidate(
            Id: "volume-c",
            Kind: RecoverySourceKind.Volume,
            DisplayName: "C",
            DevicePath: "\\\\.\\C:",
            FileSystem: "NTFS",
            SizeBytes: 100,
            SectorSizeBytes: 512,
            DiskIndex: 1,
            VolumeIdentity: "VOL-A",
            SourcePath: "C:\\",
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: true);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Code == "same-volume");
    }

    [Fact]
    public void RejectsSameVolumeForPartitionSource()
    {
        var destination = CreateTemporaryDirectory();
        var topology = new FakeStorageTopologyService();
        topology.Map(destination, "VOL-A", 2);

        var source = new SourceCandidate(
            Id: "partition-2-1",
            Kind: RecoverySourceKind.Partition,
            DisplayName: "Partition D2:P1",
            DevicePath: "\\\\.\\Harddisk2Partition1",
            FileSystem: "NTFS",
            SizeBytes: 100,
            SectorSizeBytes: 512,
            DiskIndex: 2,
            VolumeIdentity: "VOL-A",
            SourcePath: "D:\\",
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: true);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Code == "same-volume");
    }

    [Fact]
    public void RejectsSameVolumeWhenVolumeIdentityDiffersOnlyByTrailingSlash()
    {
        var destination = CreateTemporaryDirectory();
        var topology = new FakeStorageTopologyService();
        topology.Map(destination, @"\\?\Volume{ABCDEF}\", 2);

        var source = new SourceCandidate(
            Id: "vss-snapshot",
            Kind: RecoverySourceKind.Volume,
            DisplayName: "VSS Snapshot",
            DevicePath: @"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
            FileSystem: "NTFS (VSS)",
            SizeBytes: 100,
            SectorSizeBytes: 512,
            DiskIndex: 1,
            VolumeIdentity: @"\\?\Volume{ABCDEF}",
            SourcePath: @"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\",
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: true);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Code == "same-volume");
    }

    [Fact]
    public void RejectsSameDiskForPhysicalDiskSource()
    {
        var destination = CreateTemporaryDirectory();
        var topology = new FakeStorageTopologyService();
        topology.Map(destination, "VOL-D", 3);

        var source = new SourceCandidate(
            Id: "physical-3",
            Kind: RecoverySourceKind.PhysicalDisk,
            DisplayName: "Disk 3",
            DevicePath: "\\\\.\\PhysicalDrive3",
            FileSystem: null,
            SizeBytes: 100,
            SectorSizeBytes: 512,
            DiskIndex: 3,
            VolumeIdentity: null,
            SourcePath: null,
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: true);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Code == "same-disk");
    }

    [Fact]
    public void AcceptsDifferentDiskAndVolume()
    {
        var destination = CreateTemporaryDirectory();
        var topology = new FakeStorageTopologyService();
        topology.Map(destination, "VOL-Z", 8);

        var source = new SourceCandidate(
            Id: "physical-1",
            Kind: RecoverySourceKind.PhysicalDisk,
            DisplayName: "Disk 1",
            DevicePath: "\\\\.\\PhysicalDrive1",
            FileSystem: null,
            SizeBytes: 100,
            SectorSizeBytes: 512,
            DiskIndex: 1,
            VolumeIdentity: null,
            SourcePath: null,
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: true);

        Assert.True(result.IsValid);
        Assert.DoesNotContain(result.Issues, i => i.Severity == ValidationSeverity.Error);
    }

    [Fact]
    public void EmitsWarningWhenNotElevated()
    {
        var destination = CreateTemporaryDirectory();
        var topology = new FakeStorageTopologyService();
        topology.Map(destination, "VOL-X", 7);

        var source = new SourceCandidate(
            Id: "image-1",
            Kind: RecoverySourceKind.ImageFile,
            DisplayName: "Image",
            DevicePath: null,
            FileSystem: null,
            SizeBytes: 100,
            SectorSizeBytes: null,
            DiskIndex: 3,
            VolumeIdentity: "VOL-Y",
            SourcePath: "E:\\sample.img",
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: false);

        Assert.Contains(result.Issues, i => i.Code == "not-elevated");
    }

    [Fact]
    public void RejectsSameVolumeWhenVolumeIsResolvedFromMountedSourcePath()
    {
        var root = CreateTemporaryDirectory();
        var mountPath = Path.Combine(root, "mounts", "data");
        var destination = Path.Combine(mountPath, "recovery-target");
        Directory.CreateDirectory(mountPath);
        Directory.CreateDirectory(destination);

        var topology = new FakeStorageTopologyService();
        topology.Map(root, "VOL-ROOT", 0);
        topology.Map(mountPath, "VOL-DATA", 2);

        var source = new SourceCandidate(
            Id: "volume-mounted",
            Kind: RecoverySourceKind.Volume,
            DisplayName: "MountedData",
            DevicePath: "\\\\.\\Harddisk2Partition1",
            FileSystem: "NTFS",
            SizeBytes: 100,
            SectorSizeBytes: 4096,
            DiskIndex: 2,
            VolumeIdentity: null,
            SourcePath: Path.Combine(mountPath, "sample.bin"),
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: true);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Code == "same-volume");
    }

    [Fact]
    public void RejectsSameVolumeForImageSourceInNestedMountLayout()
    {
        var root = CreateTemporaryDirectory();
        var mountPath = Path.Combine(root, "volumes", "archive");
        var destination = Path.Combine(mountPath, "exports");
        Directory.CreateDirectory(mountPath);
        Directory.CreateDirectory(destination);

        var topology = new FakeStorageTopologyService();
        topology.Map(root, "VOL-ROOT", 0);
        topology.Map(mountPath, "VOL-ARCHIVE", 4);

        var source = new SourceCandidate(
            Id: "img-mounted",
            Kind: RecoverySourceKind.ImageFile,
            DisplayName: "ArchiveImage",
            DevicePath: null,
            FileSystem: null,
            SizeBytes: 1024,
            SectorSizeBytes: 512,
            DiskIndex: null,
            VolumeIdentity: null,
            SourcePath: Path.Combine(mountPath, "archive.dd"),
            ReadOnlyEnforced: true);

        var validator = new SourceDestinationSafetyValidator(topology);
        var result = validator.Validate(source, destination, isElevated: true);

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, i => i.Code == "same-volume-image");
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "fr-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeStorageTopologyService : IStorageTopologyService
    {
        private readonly List<(string Prefix, string? VolumeId, int? DiskIndex)> _entries = [];

        public void Map(string path, string? volumeId, int? diskIndex)
        {
            _entries.Add((Normalize(path), volumeId, diskIndex));
        }

        public int? TryGetDiskIndexFromPath(string path)
        {
            var normalized = Normalize(path);
            var match = _entries
                .Where(e => normalized.StartsWith(e.Prefix, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(e => e.Prefix.Length)
                .FirstOrDefault();

            return match.DiskIndex;
        }

        public string? TryGetVolumeIdFromPath(string path)
        {
            var normalized = Normalize(path);
            var match = _entries
                .Where(e => normalized.StartsWith(e.Prefix, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(e => e.Prefix.Length)
                .FirstOrDefault();

            return match.VolumeId;
        }

        public int? TryGetSectorSizeFromPath(string path)
        {
            _ = path;
            return 512;
        }

        public IReadOnlyList<string> GetMountPathsForVolumeId(string volumeId)
        {
            _ = volumeId;
            return [];
        }

        private static string Normalize(string path)
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
        }
    }
}
