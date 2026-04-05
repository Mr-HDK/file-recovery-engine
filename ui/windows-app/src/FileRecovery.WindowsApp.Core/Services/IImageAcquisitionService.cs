using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public interface IImageAcquisitionService
{
    Task<ImageAcquisitionResult> AcquireImageAsync(
        ImageAcquisitionRequest request,
        IProgress<ImageAcquisitionProgress>? progress,
        CancellationToken cancellationToken);
}
