using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public interface IWinPeRuntimeProbe
{
    string? GetEnvironmentVariable(string name);

    bool MiniNtRegistryKeyExists();

    bool CriticalStorageDriverExists(string driverFileName);

    IReadOnlyList<VisibleVolume> GetVisibleVolumes();
}
