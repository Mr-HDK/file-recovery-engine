using FileRecovery.WindowsApp.Core.Engine;
using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Tests;

public sealed class ReadPreviewScannerTests
{
    [Fact]
    public async Task RunAsyncReturnsDeterministicResult()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), "fr-preview", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDirectory);
        var imagePath = Path.Combine(tempDirectory, "sample.img");
        await File.WriteAllBytesAsync(imagePath, new byte[8192]);

        var source = new SourceCandidate(
            Id: "image-sample",
            Kind: RecoverySourceKind.ImageFile,
            DisplayName: "Sample image",
            DevicePath: null,
            FileSystem: null,
            SizeBytes: 8192,
            SectorSizeBytes: null,
            DiskIndex: null,
            VolumeIdentity: null,
            SourcePath: imagePath,
            ReadOnlyEnforced: true);

        var scanner = new ReadPreviewScanner();
        var result = await scanner.RunAsync(
            source,
            maxBytes: 4096,
            chunkSize: 1024,
            cancellationToken: CancellationToken.None,
            progress: null);

        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        if (!NativeEngineProbe.IsHealthy())
        {
            Assert.False(result.Succeeded);
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
        }
        else
        {
            Assert.InRange(result.StatusCode, -300, 20);
        }
    }
}
