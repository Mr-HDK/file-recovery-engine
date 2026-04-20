using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public interface IWinPeRuntimeService
{
    RuntimeEnvironmentProfile GetRuntimeProfile();

    OfflineStorageReadinessReport BuildOfflineStorageReadiness(
        IEnumerable<SourceCandidate> sources,
        string? destinationPath);
}
