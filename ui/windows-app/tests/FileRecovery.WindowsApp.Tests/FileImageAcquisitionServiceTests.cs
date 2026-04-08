using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Services;
using System.Security.Cryptography;
using System.Text.Json;

namespace FileRecovery.WindowsApp.Tests;

public sealed class FileImageAcquisitionServiceTests
{
    [Fact]
    public async Task AcquireImageAsyncCopiesBytesAndWritesCompletedState()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source.bin");
        var destinationPath = Path.Combine(tempRoot, "output.img");

        var sourceBytes = BuildBytes(220_000);
        await File.WriteAllBytesAsync(sourcePath, sourceBytes);

        var service = new FileImageAcquisitionService();
        var progressSnapshots = new List<ImageAcquisitionProgress>();
        var result = await service.AcquireImageAsync(
            new ImageAcquisitionRequest(
                SourcePath: sourcePath,
                DestinationImagePath: destinationPath,
                ChunkSizeBytes: 64 * 1024),
            new Progress<ImageAcquisitionProgress>(progressSnapshots.Add),
            CancellationToken.None);

        Assert.False(result.Resumed);
        Assert.Equal(ImageReadErrorPolicy.ContinueWithZeroFill, result.ReadErrorPolicy);
        Assert.Equal(0, result.ReadErrorChunks);
        Assert.Equal(0, result.ZeroFilledBytes);
        Assert.Equal(sourcePath, result.SourcePath);
        Assert.Equal(destinationPath, result.DestinationImagePath);
        Assert.Equal(sourceBytes.Length, result.BytesWritten);
        Assert.Equal(result.SourceSha256Hex, result.DestinationSha256Hex);
        Assert.Equal(await ComputeSha256HexAsync(sourcePath), result.SourceSha256Hex);
        Assert.Equal(await ComputeSha256HexAsync(destinationPath), result.DestinationSha256Hex);
        Assert.Equal(sourceBytes, await File.ReadAllBytesAsync(destinationPath));
        Assert.True(progressSnapshots.Count > 0);
        Assert.True(progressSnapshots[^1].PercentComplete >= 100.0);

        var state = await ReadJsonAsync(result.StateLogPath);
        Assert.Equal("completed", state.RootElement.GetProperty("status").GetString());
        Assert.Equal(sourceBytes.Length, state.RootElement.GetProperty("bytesWritten").GetInt64());
        Assert.Equal((int)ImageReadErrorPolicy.ContinueWithZeroFill, state.RootElement.GetProperty("readErrorPolicy").GetInt32());
        Assert.Equal(0, state.RootElement.GetProperty("readErrorChunks").GetInt32());
        Assert.Equal(0, state.RootElement.GetProperty("zeroFilledBytes").GetInt64());
    }

    [Fact]
    public async Task AcquireImageAsyncResumesWhenCheckpointMatches()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source.bin");
        var destinationPath = Path.Combine(tempRoot, "resume.img");
        var statePath = destinationPath + ".acquisition.json";

        var sourceBytes = BuildBytes(320_000);
        await File.WriteAllBytesAsync(sourcePath, sourceBytes);

        const int chunkSize = 64 * 1024;
        const int resumeBytes = 128_000;
        await File.WriteAllBytesAsync(destinationPath, sourceBytes[..resumeBytes]);

        await WriteStateAsync(
            statePath,
            new
            {
                sourcePath = Path.GetFullPath(sourcePath),
                destinationImagePath = Path.GetFullPath(destinationPath),
                sourceSizeBytes = sourceBytes.Length,
                chunkSizeBytes = chunkSize,
                bytesWritten = resumeBytes,
                startedUtc = "2026-04-05T12:00:00+00:00",
                updatedUtc = "2026-04-05T12:01:00+00:00",
                status = "in_progress",
            });

        var service = new FileImageAcquisitionService();
        var result = await service.AcquireImageAsync(
            new ImageAcquisitionRequest(
                SourcePath: sourcePath,
                DestinationImagePath: destinationPath,
                StateLogPath: statePath,
                ChunkSizeBytes: chunkSize,
                AllowResume: true),
            progress: null,
            CancellationToken.None);

        Assert.True(result.Resumed);
        Assert.Equal(0, result.ReadErrorChunks);
        Assert.Equal(0, result.ZeroFilledBytes);
        Assert.Equal(sourceBytes, await File.ReadAllBytesAsync(destinationPath));

        var state = await ReadJsonAsync(statePath);
        Assert.Equal("completed", state.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task AcquireImageAsyncFailsWhenResumePrefixMismatches()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source.bin");
        var destinationPath = Path.Combine(tempRoot, "mismatch.img");
        var statePath = destinationPath + ".acquisition.json";

        var sourceBytes = BuildBytes(160_000);
        await File.WriteAllBytesAsync(sourcePath, sourceBytes);

        const int chunkSize = 64 * 1024;
        const int resumeBytes = 96_000;
        var mismatchedDestination = sourceBytes[..resumeBytes].ToArray();
        mismatchedDestination[2048] ^= 0x5A;
        await File.WriteAllBytesAsync(destinationPath, mismatchedDestination);

        await WriteStateAsync(
            statePath,
            new
            {
                sourcePath = Path.GetFullPath(sourcePath),
                destinationImagePath = Path.GetFullPath(destinationPath),
                sourceSizeBytes = sourceBytes.Length,
                chunkSizeBytes = chunkSize,
                bytesWritten = resumeBytes,
                startedUtc = "2026-04-05T12:00:00+00:00",
                updatedUtc = "2026-04-05T12:01:00+00:00",
                status = "in_progress",
            });

        var service = new FileImageAcquisitionService();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.AcquireImageAsync(
                new ImageAcquisitionRequest(
                    SourcePath: sourcePath,
                    DestinationImagePath: destinationPath,
                    StateLogPath: statePath,
                    ChunkSizeBytes: chunkSize,
                    AllowResume: true),
                progress: null,
                CancellationToken.None));

        var state = await ReadJsonAsync(statePath);
        Assert.Equal("failed", state.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task AcquireImageAsyncDoesNotResumeWhenCheckpointContainsReadErrors()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source.bin");
        var destinationPath = Path.Combine(tempRoot, "checkpoint-errors.img");
        var statePath = destinationPath + ".acquisition.json";

        var sourceBytes = BuildBytes(180_000);
        await File.WriteAllBytesAsync(sourcePath, sourceBytes);
        await File.WriteAllBytesAsync(destinationPath, sourceBytes[..64_000]);

        await WriteStateAsync(
            statePath,
            new
            {
                sourcePath = Path.GetFullPath(sourcePath),
                destinationImagePath = Path.GetFullPath(destinationPath),
                sourceSizeBytes = sourceBytes.Length,
                chunkSizeBytes = 64 * 1024,
                bytesWritten = 64_000,
                startedUtc = "2026-04-09T10:00:00+00:00",
                updatedUtc = "2026-04-09T10:01:00+00:00",
                status = "in_progress",
                readErrorPolicy = 1,
                readErrorChunks = 2,
                zeroFilledBytes = 131072,
            });

        var service = new FileImageAcquisitionService();
        var result = await service.AcquireImageAsync(
            new ImageAcquisitionRequest(
                SourcePath: sourcePath,
                DestinationImagePath: destinationPath,
                StateLogPath: statePath,
                ChunkSizeBytes: 64 * 1024,
                AllowResume: true,
                ReadErrorPolicy: ImageReadErrorPolicy.ContinueWithZeroFill),
            progress: null,
            CancellationToken.None);

        Assert.False(result.Resumed);
        Assert.Equal(0, result.ReadErrorChunks);
        Assert.Equal(0, result.ZeroFilledBytes);
        Assert.Equal(sourceBytes, await File.ReadAllBytesAsync(destinationPath));
    }

    private static byte[] BuildBytes(int length)
    {
        var bytes = new byte[length];
        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)((index * 31) % 251);
        }

        return bytes;
    }

    private static async Task<string> ComputeSha256HexAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sha = SHA256.Create();
        return Convert.ToHexString(await sha.ComputeHashAsync(stream)).ToLowerInvariant();
    }

    private static async Task<JsonDocument> ReadJsonAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return await JsonDocument.ParseAsync(stream);
    }

    private static Task WriteStateAsync<TState>(string path, TState state)
    {
        var json = JsonSerializer.Serialize(state, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        return File.WriteAllTextAsync(path, json);
    }

    private static string CreateTemporaryDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "fr-tests-imaging", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
