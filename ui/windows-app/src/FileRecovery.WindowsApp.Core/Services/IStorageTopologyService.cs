namespace FileRecovery.WindowsApp.Core.Services;

public interface IStorageTopologyService
{
    string? TryGetVolumeIdFromPath(string path);

    int? TryGetDiskIndexFromPath(string path);

    int? TryGetSectorSizeFromPath(string path);

    IReadOnlyList<string> GetMountPathsForVolumeId(string volumeId);
}
