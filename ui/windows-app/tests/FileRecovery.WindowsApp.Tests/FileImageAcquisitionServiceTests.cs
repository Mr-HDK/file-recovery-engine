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
        Assert.False(result.SourceIsNetwork);
        Assert.False(result.ConstrainedNetworkIo);
        Assert.Equal(RemoteAgentMode.Disabled, result.RemoteAgentMode);
        Assert.Null(result.RemoteAgentEndpoint);
        Assert.Equal(RemoteExecutionStatus.NotRequested, result.RemoteExecutionStatus);
        Assert.Equal(RemoteExecutionErrorCode.None, result.RemoteExecutionErrorCode);
        Assert.Null(result.RemoteExecutionMessage);
        Assert.Null(result.RemoteExecutionIntegrityHash);
        Assert.Null(result.ChainOfCustodyLogPath);
        Assert.Equal(0, result.NetworkCheckpointCount);
        Assert.Null(result.UnreadableRangesManifestPath);
        Assert.Equal(sourceBytes, await File.ReadAllBytesAsync(destinationPath));
        Assert.True(progressSnapshots.Count > 0);
        Assert.True(progressSnapshots[^1].PercentComplete >= 100.0);

        var state = await ReadJsonAsync(result.StateLogPath);
        Assert.Equal("completed", state.RootElement.GetProperty("status").GetString());
        Assert.Equal(sourceBytes.Length, state.RootElement.GetProperty("bytesWritten").GetInt64());
        Assert.Equal((int)ImageReadErrorPolicy.ContinueWithZeroFill, state.RootElement.GetProperty("readErrorPolicy").GetInt32());
        Assert.Equal(0, state.RootElement.GetProperty("readErrorChunks").GetInt32());
        Assert.Equal(0, state.RootElement.GetProperty("zeroFilledBytes").GetInt64());
        Assert.False(state.RootElement.GetProperty("sourceIsNetwork").GetBoolean());
        Assert.False(state.RootElement.GetProperty("constrainedNetworkIo").GetBoolean());
        Assert.Equal(0, state.RootElement.GetProperty("networkCheckpointCount").GetInt32());
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

    [Fact]
    public async Task AcquireImageAsyncNetworkModeWritesCustodyLogAndNetworkState()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source-network.bin");
        var destinationPath = Path.Combine(tempRoot, "network-output.img");
        var custodyPath = Path.Combine(tempRoot, "network-custody.jsonl");

        var sourceBytes = BuildBytes(420_000);
        await File.WriteAllBytesAsync(sourcePath, sourceBytes);

        var service = new FileImageAcquisitionService();
        var result = await service.AcquireImageAsync(
            new ImageAcquisitionRequest(
                SourcePath: sourcePath,
                DestinationImagePath: destinationPath,
                ChunkSizeBytes: 64 * 1024,
                SourceIsNetwork: true,
                EnableConstrainedNetworkIo: true,
                ConstrainedNetworkChunkSizeBytes: 128 * 1024,
                RemoteAgentMode: RemoteAgentMode.Optional,
                RemoteAgentEndpoint: "agent://nas-sidecar",
                ChainOfCustodyLogPath: custodyPath),
            progress: null,
            CancellationToken.None);

        Assert.True(result.SourceIsNetwork);
        Assert.True(result.ConstrainedNetworkIo);
        Assert.Equal(RemoteAgentMode.Optional, result.RemoteAgentMode);
        Assert.Equal("agent://nas-sidecar", result.RemoteAgentEndpoint);
        Assert.Equal(RemoteExecutionStatus.Succeeded, result.RemoteExecutionStatus);
        Assert.Equal(RemoteExecutionErrorCode.None, result.RemoteExecutionErrorCode);
        Assert.False(string.IsNullOrWhiteSpace(result.RemoteExecutionIntegrityHash));
        Assert.Equal(custodyPath, result.ChainOfCustodyLogPath);
        Assert.Null(result.UnreadableRangesManifestPath);
        Assert.True(File.Exists(custodyPath));

        var custodyLines = await File.ReadAllLinesAsync(custodyPath);
        Assert.True(custodyLines.Length >= 2);
        using var startEvent = JsonDocument.Parse(custodyLines[0]);
        using var completionEvent = JsonDocument.Parse(custodyLines[^1]);
        Assert.Equal("network_acquisition_started", startEvent.RootElement.GetProperty("event_name").GetString());
        Assert.Equal("network_acquisition_completed", completionEvent.RootElement.GetProperty("event_name").GetString());

        var state = await ReadJsonAsync(result.StateLogPath);
        Assert.True(state.RootElement.GetProperty("sourceIsNetwork").GetBoolean());
        Assert.True(state.RootElement.GetProperty("constrainedNetworkIo").GetBoolean());
        Assert.Equal((int)RemoteAgentMode.Optional, state.RootElement.GetProperty("remoteAgentMode").GetInt32());
        Assert.Equal("agent://nas-sidecar", state.RootElement.GetProperty("remoteAgentEndpoint").GetString());
        Assert.Equal((int)RemoteExecutionStatus.Succeeded, state.RootElement.GetProperty("remoteExecutionStatus").GetInt32());
        Assert.Equal((int)RemoteExecutionErrorCode.None, state.RootElement.GetProperty("remoteExecutionErrorCode").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(state.RootElement.GetProperty("remoteExecutionIntegrityHash").GetString()));
    }

    [Fact]
    public async Task AcquireImageAsyncThrowsWhenRemoteAgentRequiredWithoutEndpoint()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source-remote.bin");
        var destinationPath = Path.Combine(tempRoot, "remote-output.img");
        await File.WriteAllBytesAsync(sourcePath, BuildBytes(65_536));

        var service = new FileImageAcquisitionService();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.AcquireImageAsync(
                new ImageAcquisitionRequest(
                    SourcePath: sourcePath,
                    DestinationImagePath: destinationPath,
                    ChunkSizeBytes: 64 * 1024,
                    SourceIsNetwork: true,
                    RemoteAgentMode: RemoteAgentMode.Required),
                progress: null,
                CancellationToken.None));
    }

    [Fact]
    public async Task AcquireImageAsyncThrowsWhenThroughputLimitIsNotPositive()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source-throughput.bin");
        var destinationPath = Path.Combine(tempRoot, "throughput-output.img");
        await File.WriteAllBytesAsync(sourcePath, BuildBytes(65_536));

        var service = new FileImageAcquisitionService();
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.AcquireImageAsync(
                new ImageAcquisitionRequest(
                    SourcePath: sourcePath,
                    DestinationImagePath: destinationPath,
                    ChunkSizeBytes: 64 * 1024,
                    SourceIsNetwork: true,
                    MaxNetworkThroughputBytesPerSecond: 0),
                progress: null,
                CancellationToken.None));
    }

    [Fact]
    public async Task AcquireImageAsyncThrowsWhenRemoteAgentEndpointIsUnreachable()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source-remote-unreachable.bin");
        var destinationPath = Path.Combine(tempRoot, "remote-unreachable-output.img");
        await File.WriteAllBytesAsync(sourcePath, BuildBytes(65_536));

        var service = new FileImageAcquisitionService();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.AcquireImageAsync(
                new ImageAcquisitionRequest(
                    SourcePath: sourcePath,
                    DestinationImagePath: destinationPath,
                    ChunkSizeBytes: 64 * 1024,
                    SourceIsNetwork: true,
                    RemoteAgentMode: RemoteAgentMode.Optional,
                    RemoteAgentEndpoint: "nas-sidecar"),
                progress: null,
                CancellationToken.None));

        Assert.Contains("Remote agent handshake failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AcquireImageAsyncFaultInjectionEmitsUnreadableRangeManifest()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source-fault.bin");
        var destinationPath = Path.Combine(tempRoot, "fault-output.img");
        var sourceBytes = BuildBytes(512 * 1024);
        await File.WriteAllBytesAsync(sourcePath, sourceBytes);

        var service = new FileImageAcquisitionService((path, chunkSizeBytes) =>
        {
            var fileStream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                chunkSizeBytes,
                FileOptions.SequentialScan);
            return new FaultInjectingReadStream(fileStream, failEveryNReads: 3);
        });

        var result = await service.AcquireImageAsync(
            new ImageAcquisitionRequest(
                SourcePath: sourcePath,
                DestinationImagePath: destinationPath,
                ChunkSizeBytes: 64 * 1024,
                SourceIsNetwork: true,
                ReadErrorPolicy: ImageReadErrorPolicy.ContinueWithZeroFill),
            progress: null,
            CancellationToken.None);

        Assert.True(result.ReadErrorChunks > 0);
        Assert.True(result.ZeroFilledBytes > 0);
        Assert.False(string.IsNullOrWhiteSpace(result.UnreadableRangesManifestPath));
        Assert.True(File.Exists(result.UnreadableRangesManifestPath!));

        using var manifest = await ReadJsonAsync(result.UnreadableRangesManifestPath!);
        var root = manifest.RootElement;
        Assert.Equal(result.ReadErrorChunks, root.GetProperty("rangeCount").GetInt32());
        Assert.Equal(result.ZeroFilledBytes, root.GetProperty("zeroFilledBytes").GetInt64());
        Assert.Equal((int)ImageReadErrorPolicy.ContinueWithZeroFill, root.GetProperty("readErrorPolicy").GetInt32());
    }

    [Fact]
    public async Task AcquireImageAsyncFailsWhenRemoteAgentReturnsMismatchedRequestId()
    {
        var tempRoot = CreateTemporaryDirectory();
        var sourcePath = Path.Combine(tempRoot, "source-remote-mismatch.bin");
        var destinationPath = Path.Combine(tempRoot, "remote-mismatch-output.img");
        await File.WriteAllBytesAsync(sourcePath, BuildBytes(65_536));

        var service = new FileImageAcquisitionService(
            sourceStreamFactory: null,
            remoteAgentRuntime: new MismatchedRequestIdRuntime());

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.AcquireImageAsync(
                new ImageAcquisitionRequest(
                    SourcePath: sourcePath,
                    DestinationImagePath: destinationPath,
                    ChunkSizeBytes: 64 * 1024,
                    SourceIsNetwork: true,
                    RemoteAgentMode: RemoteAgentMode.Required,
                    RemoteAgentEndpoint: "https://agent.example/exec"),
                progress: null,
                CancellationToken.None));

        Assert.Contains("Remote agent handshake failed", ex.Message, StringComparison.OrdinalIgnoreCase);
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

    private sealed class FaultInjectingReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly int _failEveryNReads;
        private int _readCalls;

        public FaultInjectingReadStream(Stream inner, int failEveryNReads)
        {
            _inner = inner;
            _failEveryNReads = failEveryNReads;
        }

        public override bool CanRead => _inner.CanRead;
        public override bool CanSeek => _inner.CanSeek;
        public override bool CanWrite => false;
        public override long Length => _inner.Length;

        public override long Position
        {
            get => _inner.Position;
            set => _inner.Position = value;
        }

        public override void Flush() => _inner.Flush();

        public override int Read(byte[] buffer, int offset, int count)
        {
            _readCalls++;
            if (_failEveryNReads > 0 && _readCalls % _failEveryNReads == 0)
            {
                throw new IOException("Injected intermittent read failure.");
            }

            return _inner.Read(buffer, offset, count);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _readCalls++;
            if (_failEveryNReads > 0 && _readCalls % _failEveryNReads == 0)
            {
                throw new IOException("Injected intermittent read failure.");
            }

            return _inner.ReadAsync(buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            return _inner.DisposeAsync();
        }
    }

    private sealed class MismatchedRequestIdRuntime : IRemoteAgentRuntime
    {
        public Task<RemoteAgentResponse> ExecuteAsync(RemoteAgentRequest request, CancellationToken cancellationToken)
        {
            return Task.FromResult(
                new RemoteAgentResponse(
                    RequestId: Guid.NewGuid(),
                    Status: RemoteExecutionStatus.Succeeded,
                    ErrorCode: RemoteExecutionErrorCode.None,
                    Message: "ok",
                    RespondedUtc: DateTimeOffset.UtcNow,
                    Integrity: request.Integrity));
        }
    }
}
