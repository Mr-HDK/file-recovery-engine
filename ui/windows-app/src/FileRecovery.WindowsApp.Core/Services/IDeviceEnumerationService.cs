using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public interface IDeviceEnumerationService
{
    Task<SourceEnumerationResult> EnumerateAsync(CancellationToken cancellationToken);

    Task<SourceCandidate> BuildImageSourceAsync(string imagePath, CancellationToken cancellationToken);
}
