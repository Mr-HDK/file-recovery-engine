using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public interface IStorageHealthTelemetryService
{
    Task<StorageHealthSnapshot> GetSnapshotAsync(CancellationToken cancellationToken);
}
