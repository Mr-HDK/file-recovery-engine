using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Services;

namespace FileRecovery.WindowsApp.Tests;

public sealed class WindowsDeviceEnumerationServiceTests
{
    [Fact]
    public async Task BuildImageSourceAsyncReturnsImageCandidateWithTopologyMetadata()
    {
        var tempRoot = CreateTemporaryDirectory();
        var imagePath = Path.Combine(tempRoot, "sample.img");
        await File.WriteAllBytesAsync(imagePath, new byte[4096]);

        var topology = new FakeStorageTopologyService();
        topology.Map(imagePath, "VOL-IMG", 7, 4096);
        topology.MapMountPaths("VOL-IMG", "E:\\", "E:\\mounts\\archive\\");

        var service = new WindowsDeviceEnumerationService(topology);
        var candidate = await service.BuildImageSourceAsync(imagePath, CancellationToken.None);

        Assert.Equal(RecoverySourceKind.ImageFile, candidate.Kind);
        Assert.True(candidate.ReadOnlyEnforced);
        Assert.Equal(Path.GetFullPath(imagePath), candidate.SourcePath);
        Assert.Equal("VOL-IMG", candidate.VolumeIdentity);
        Assert.Equal(7, candidate.DiskIndex);
        Assert.Equal(4096, candidate.SectorSizeBytes);
        Assert.Equal("E:\\;E:\\mounts\\archive\\", candidate.MountedPaths);
        Assert.Equal("Image file source", candidate.PartitionInfo);
    }

    [Fact]
    public async Task BuildImageSourceAsyncThrowsFileNotFoundWhenImageMissing()
    {
        var topology = new FakeStorageTopologyService();
        var service = new WindowsDeviceEnumerationService(topology);

        var missingPath = Path.Combine(CreateTemporaryDirectory(), "missing.dd");
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            service.BuildImageSourceAsync(missingPath, CancellationToken.None));
    }

    [Fact]
    public async Task BuildImageSourceAsyncHonorsCancellationToken()
    {
        var tempRoot = CreateTemporaryDirectory();
        var imagePath = Path.Combine(tempRoot, "sample.raw");
        await File.WriteAllBytesAsync(imagePath, new byte[2048]);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var topology = new FakeStorageTopologyService();
        var service = new WindowsDeviceEnumerationService(topology);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.BuildImageSourceAsync(imagePath, cts.Token));
    }

    [Fact]
    public async Task BuildNetworkImageSourceAsyncReturnsNetworkCandidateWithEndpointHint()
    {
        var tempRoot = CreateTemporaryDirectory();
        var imagePath = Path.Combine(tempRoot, "nas-snapshot.img");
        await File.WriteAllBytesAsync(imagePath, new byte[8192]);

        var topology = new FakeStorageTopologyService();
        topology.Map(imagePath, "VOL-NAS", 3, 4096);
        topology.MapMountPaths("VOL-NAS", "N:\\");

        var service = new WindowsDeviceEnumerationService(topology);
        var candidate = await service.BuildNetworkImageSourceAsync(
            new NetworkSourceRequest(NetworkSourceProtocol.Smb, imagePath, "nas01/archive"),
            CancellationToken.None);

        Assert.Equal(RecoverySourceKind.ImageFile, candidate.Kind);
        Assert.True(candidate.ReadOnlyEnforced);
        Assert.True(candidate.IsNetworkSource);
        Assert.Equal("SMB", candidate.NetworkProtocol);
        Assert.Equal("nas01/archive", candidate.NetworkEndpoint);
        Assert.Equal("SMB mounted image source", candidate.PartitionInfo);
        Assert.Equal(Path.GetFullPath(imagePath), candidate.SourcePath);
        Assert.Equal("VOL-NAS", candidate.VolumeIdentity);
        Assert.Equal(3, candidate.DiskIndex);
        Assert.Equal(4096, candidate.SectorSizeBytes);
    }

    [Fact]
    public async Task BuildNetworkImageSourceAsyncThrowsWhenPathMissing()
    {
        var topology = new FakeStorageTopologyService();
        var service = new WindowsDeviceEnumerationService(topology);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.BuildNetworkImageSourceAsync(
                new NetworkSourceRequest(NetworkSourceProtocol.Nfs, "   ", EndpointHint: null),
                CancellationToken.None));
    }

    [Fact]
    public async Task BuildNetworkImageSourceAsyncThrowsFileNotFoundWhenImageMissing()
    {
        var topology = new FakeStorageTopologyService();
        var service = new WindowsDeviceEnumerationService(topology);
        var missingPath = Path.Combine(CreateTemporaryDirectory(), "missing-network.img");

        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            service.BuildNetworkImageSourceAsync(
                new NetworkSourceRequest(NetworkSourceProtocol.Smb, missingPath),
                CancellationToken.None));
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "fr-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class FakeStorageTopologyService : IStorageTopologyService
    {
        private readonly Dictionary<string, (string? VolumeId, int? DiskIndex, int? SectorSize)> _pathMap =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, IReadOnlyList<string>> _mountPathMap =
            new(StringComparer.OrdinalIgnoreCase);

        public void Map(string path, string? volumeId, int? diskIndex, int? sectorSize)
        {
            _pathMap[Normalize(path)] = (volumeId, diskIndex, sectorSize);
        }

        public void MapMountPaths(string volumeId, params string[] mountPaths)
        {
            _mountPathMap[volumeId] = mountPaths;
        }

        public string? TryGetVolumeIdFromPath(string path)
        {
            return TryGetEntry(path)?.VolumeId;
        }

        public int? TryGetDiskIndexFromPath(string path)
        {
            return TryGetEntry(path)?.DiskIndex;
        }

        public int? TryGetSectorSizeFromPath(string path)
        {
            return TryGetEntry(path)?.SectorSize;
        }

        public IReadOnlyList<string> GetMountPathsForVolumeId(string volumeId)
        {
            return _mountPathMap.TryGetValue(volumeId, out var paths)
                ? paths
                : [];
        }

        private (string? VolumeId, int? DiskIndex, int? SectorSize)? TryGetEntry(string path)
        {
            var normalized = Normalize(path);
            var match = _pathMap
                .Where(kvp => normalized.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(kvp => kvp.Key.Length)
                .Select(kvp => kvp.Value)
                .FirstOrDefault();

            return match == default ? null : match;
        }

        private static string Normalize(string path)
        {
            return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant();
        }
    }
}
