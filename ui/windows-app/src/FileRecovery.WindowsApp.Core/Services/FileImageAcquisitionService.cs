using FileRecovery.WindowsApp.Core.Models;
using System.Security.Cryptography;
using System.Text.Json;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class FileImageAcquisitionService : IImageAcquisitionService
{
    private const int MinChunkSizeBytes = 64 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public async Task<ImageAcquisitionResult> AcquireImageAsync(
        ImageAcquisitionRequest request,
        IProgress<ImageAcquisitionProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.ChunkSizeBytes < MinChunkSizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                $"Chunk size must be at least {MinChunkSizeBytes} bytes.");
        }
        if (request.MaxReadErrorChunks < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Max read error chunks must be non-negative.");
        }

        var sourcePath = Path.GetFullPath(request.SourcePath);
        var destinationPath = Path.GetFullPath(request.DestinationImagePath);
        if (string.Equals(sourcePath, destinationPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Source and destination image paths must be different.");
        }

        var stateLogPath = string.IsNullOrWhiteSpace(request.StateLogPath)
            ? destinationPath + ".acquisition.json"
            : Path.GetFullPath(request.StateLogPath);

        var destinationDirectory = Path.GetDirectoryName(destinationPath);
        if (string.IsNullOrWhiteSpace(destinationDirectory))
        {
            throw new InvalidOperationException("Destination image path must include a parent directory.");
        }

        Directory.CreateDirectory(destinationDirectory);
        var stateDirectory = Path.GetDirectoryName(stateLogPath);
        if (!string.IsNullOrWhiteSpace(stateDirectory))
        {
            Directory.CreateDirectory(stateDirectory);
        }

        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException("Source path not found.", sourcePath);
        }

        await using var sourceStream = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            request.ChunkSizeBytes,
            FileOptions.SequentialScan);

        var sourceSizeBytes = sourceStream.Length;
        var startedUtc = DateTimeOffset.UtcNow;
        var bytesWritten = 0L;
        var resumed = false;
        var sourceHashHex = string.Empty;
        var destinationHashHex = string.Empty;
        var readErrorChunks = 0;
        var zeroFilledBytes = 0L;

        if (sourceSizeBytes < 0)
        {
            throw new InvalidOperationException("Source size could not be determined.");
        }

        var checkpoint = await TryReadStateAsync(stateLogPath, cancellationToken);
        var canResume = request.AllowResume
            && checkpoint is not null
            && File.Exists(destinationPath)
            && IsCompatibleResume(
                checkpoint,
                sourcePath,
                destinationPath,
                sourceSizeBytes,
                request.ChunkSizeBytes);

        if (canResume)
        {
            startedUtc = checkpoint!.StartedUtc;
            var destinationLength = new FileInfo(destinationPath).Length;
            bytesWritten = Math.Min(Math.Min(destinationLength, checkpoint.BytesWritten), sourceSizeBytes);
            resumed = bytesWritten > 0;
            readErrorChunks = checkpoint.ReadErrorChunks;
            zeroFilledBytes = checkpoint.ZeroFilledBytes;
        }

        await WriteStateAsync(
            stateLogPath,
            BuildState(
                sourcePath,
                destinationPath,
                sourceSizeBytes,
                request.ChunkSizeBytes,
                bytesWritten,
                startedUtc,
                status: "in_progress",
                readErrorPolicy: request.ReadErrorPolicy,
                readErrorChunks: readErrorChunks,
                zeroFilledBytes: zeroFilledBytes,
                sourceSha256Hex: null,
                destinationSha256Hex: null,
                error: null),
            cancellationToken);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var lastCheckpointWrite = TimeSpan.Zero;
        var bytesAtLastSample = bytesWritten;
        var lastSampleElapsed = TimeSpan.Zero;
        using var sourceHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        try
        {
            if (resumed)
            {
                await VerifyAndHashResumePrefixAsync(
                    sourceStream,
                    destinationPath,
                    bytesWritten,
                    request.ChunkSizeBytes,
                    sourceHash,
                    cancellationToken);
            }

            await using (
                var destinationStream = new FileStream(
                    destinationPath,
                    resumed ? FileMode.Open : FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    request.ChunkSizeBytes,
                    FileOptions.SequentialScan))
            {
                destinationStream.Position = bytesWritten;
                sourceStream.Position = bytesWritten;

                progress?.Report(new ImageAcquisitionProgress(
                    BytesWritten: bytesWritten,
                    TotalBytes: sourceSizeBytes,
                    PercentComplete: Percent(bytesWritten, sourceSizeBytes),
                    ThroughputBytesPerSecond: 0,
                    Resumed: resumed,
                    ReadErrorChunks: readErrorChunks,
                    ZeroFilledBytes: zeroFilledBytes));

                var buffer = new byte[request.ChunkSizeBytes];
                while (bytesWritten < sourceSizeBytes)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var remaining = sourceSizeBytes - bytesWritten;
                    var requested = (int)Math.Min(buffer.Length, remaining);
                    var (read, zeroFilled) = await ReadSourceChunkWithPolicyAsync(
                        sourceStream,
                        buffer,
                        requested,
                        request,
                        readErrorChunks,
                        cancellationToken);
                    if (read == 0 && !zeroFilled)
                    {
                        break;
                    }

                    await destinationStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    sourceHash.AppendData(buffer, 0, read);
                    bytesWritten += read;
                    if (zeroFilled)
                    {
                        readErrorChunks++;
                        zeroFilledBytes += read;
                    }

                    var elapsed = stopwatch.Elapsed;
                    var elapsedDelta = elapsed - lastSampleElapsed;
                    var throughput = elapsedDelta.TotalSeconds > 0
                        ? (bytesWritten - bytesAtLastSample) / elapsedDelta.TotalSeconds
                        : 0;

                    progress?.Report(new ImageAcquisitionProgress(
                        BytesWritten: bytesWritten,
                        TotalBytes: sourceSizeBytes,
                        PercentComplete: Percent(bytesWritten, sourceSizeBytes),
                        ThroughputBytesPerSecond: throughput,
                        Resumed: resumed,
                        ReadErrorChunks: readErrorChunks,
                        ZeroFilledBytes: zeroFilledBytes));

                    if (elapsed - lastCheckpointWrite >= TimeSpan.FromSeconds(1))
                    {
                        await WriteStateAsync(
                            stateLogPath,
                            BuildState(
                                sourcePath,
                                destinationPath,
                                sourceSizeBytes,
                                request.ChunkSizeBytes,
                                bytesWritten,
                                startedUtc,
                                status: "in_progress",
                                readErrorPolicy: request.ReadErrorPolicy,
                                readErrorChunks: readErrorChunks,
                                zeroFilledBytes: zeroFilledBytes,
                                sourceSha256Hex: null,
                                destinationSha256Hex: null,
                                error: null),
                            cancellationToken);
                        lastCheckpointWrite = elapsed;
                    }

                    bytesAtLastSample = bytesWritten;
                    lastSampleElapsed = elapsed;
                }

                await destinationStream.FlushAsync(cancellationToken);
            }

            sourceHashHex = Convert.ToHexString(sourceHash.GetHashAndReset()).ToLowerInvariant();
            destinationHashHex = await ComputeSha256HexAsync(destinationPath, request.ChunkSizeBytes, cancellationToken);
            if (!string.Equals(sourceHashHex, destinationHashHex, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Source and destination SHA-256 digests do not match.");
            }

            var completedState = BuildState(
                sourcePath,
                destinationPath,
                sourceSizeBytes,
                request.ChunkSizeBytes,
                bytesWritten,
                startedUtc,
                status: "completed",
                readErrorPolicy: request.ReadErrorPolicy,
                readErrorChunks: readErrorChunks,
                zeroFilledBytes: zeroFilledBytes,
                sourceSha256Hex: sourceHashHex,
                destinationSha256Hex: destinationHashHex,
                error: null);
            await WriteStateAsync(stateLogPath, completedState, cancellationToken);

            return new ImageAcquisitionResult(
                SourcePath: sourcePath,
                DestinationImagePath: destinationPath,
                StateLogPath: stateLogPath,
                BytesWritten: bytesWritten,
                SourceSha256Hex: sourceHashHex,
                DestinationSha256Hex: destinationHashHex,
                Resumed: resumed,
                ReadErrorPolicy: request.ReadErrorPolicy,
                ReadErrorChunks: readErrorChunks,
                ZeroFilledBytes: zeroFilledBytes);
        }
        catch (OperationCanceledException)
        {
            await WriteStateAsync(
                stateLogPath,
                BuildState(
                    sourcePath,
                    destinationPath,
                    sourceSizeBytes,
                    request.ChunkSizeBytes,
                    bytesWritten,
                    startedUtc,
                    status: "canceled",
                    readErrorPolicy: request.ReadErrorPolicy,
                    readErrorChunks: readErrorChunks,
                    zeroFilledBytes: zeroFilledBytes,
                    sourceSha256Hex: sourceHashHex,
                    destinationSha256Hex: destinationHashHex,
                    error: "Acquisition canceled."),
                CancellationToken.None);
            throw;
        }
        catch (Exception ex)
        {
            await WriteStateAsync(
                stateLogPath,
                BuildState(
                    sourcePath,
                    destinationPath,
                    sourceSizeBytes,
                    request.ChunkSizeBytes,
                    bytesWritten,
                    startedUtc,
                    status: "failed",
                    readErrorPolicy: request.ReadErrorPolicy,
                    readErrorChunks: readErrorChunks,
                    zeroFilledBytes: zeroFilledBytes,
                    sourceSha256Hex: sourceHashHex,
                    destinationSha256Hex: destinationHashHex,
                    error: ex.Message),
                CancellationToken.None);
            throw;
        }
    }

    private static bool IsCompatibleResume(
        ImageAcquisitionState state,
        string sourcePath,
        string destinationPath,
        long sourceSizeBytes,
        int chunkSizeBytes)
    {
        return string.Equals(state.SourcePath, sourcePath, StringComparison.OrdinalIgnoreCase)
            && string.Equals(state.DestinationImagePath, destinationPath, StringComparison.OrdinalIgnoreCase)
            && state.SourceSizeBytes == sourceSizeBytes
            && state.ChunkSizeBytes == chunkSizeBytes
            && state.ReadErrorChunks == 0
            && state.ZeroFilledBytes == 0
            && state.BytesWritten >= 0;
    }

    private static async Task<(int bytesRead, bool zeroFilled)> ReadSourceChunkWithPolicyAsync(
        FileStream sourceStream,
        byte[] buffer,
        int requestedBytes,
        ImageAcquisitionRequest request,
        int currentReadErrorChunks,
        CancellationToken cancellationToken)
    {
        try
        {
            var read = await sourceStream.ReadAsync(buffer.AsMemory(0, requestedBytes), cancellationToken);
            return (read, false);
        }
        catch (IOException) when (request.ReadErrorPolicy == ImageReadErrorPolicy.ContinueWithZeroFill)
        {
            if (request.MaxReadErrorChunks > 0 && currentReadErrorChunks >= request.MaxReadErrorChunks)
            {
                throw new IOException(
                    $"Read-error chunk threshold reached ({request.MaxReadErrorChunks}).");
            }

            if (!sourceStream.CanSeek)
            {
                throw new IOException("Source stream does not support seek for zero-fill continuation.");
            }

            Array.Clear(buffer, 0, requestedBytes);
            sourceStream.Seek(requestedBytes, SeekOrigin.Current);
            return (requestedBytes, true);
        }
    }

    private static async Task VerifyAndHashResumePrefixAsync(
        FileStream sourceStream,
        string destinationPath,
        long prefixBytes,
        int chunkSizeBytes,
        IncrementalHash sourceHash,
        CancellationToken cancellationToken)
    {
        if (prefixBytes <= 0)
        {
            return;
        }

        await using var destinationStream = new FileStream(
            destinationPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            chunkSizeBytes,
            FileOptions.SequentialScan);
        if (destinationStream.Length < prefixBytes)
        {
            throw new InvalidDataException("Existing destination image is shorter than the resume checkpoint.");
        }

        sourceStream.Position = 0;
        destinationStream.Position = 0;

        var sourceBuffer = new byte[chunkSizeBytes];
        var destinationBuffer = new byte[chunkSizeBytes];
        var remaining = prefixBytes;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var chunk = (int)Math.Min(chunkSizeBytes, remaining);
            await ReadExactlyAsync(sourceStream, sourceBuffer, chunk, cancellationToken);
            await ReadExactlyAsync(destinationStream, destinationBuffer, chunk, cancellationToken);

            if (!sourceBuffer.AsSpan(0, chunk).SequenceEqual(destinationBuffer.AsSpan(0, chunk)))
            {
                throw new InvalidDataException("Existing destination image prefix does not match source bytes.");
            }

            sourceHash.AppendData(sourceBuffer, 0, chunk);
            remaining -= chunk;
        }
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        byte[] buffer,
        int count,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while validating resume prefix.");
            }

            offset += read;
        }
    }

    private static async Task<string> ComputeSha256HexAsync(
        string path,
        int chunkSizeBytes,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            chunkSizeBytes,
            FileOptions.SequentialScan);
        using var hash = SHA256.Create();
        var digest = await hash.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    private static async Task<ImageAcquisitionState?> TryReadStateAsync(
        string stateLogPath,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(stateLogPath))
        {
            return null;
        }

        await using var stream = new FileStream(
            stateLogPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 32 * 1024,
            FileOptions.SequentialScan);
        return await JsonSerializer.DeserializeAsync<ImageAcquisitionState>(stream, SerializerOptions, cancellationToken);
    }

    private static async Task WriteStateAsync(
        string stateLogPath,
        ImageAcquisitionState state,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            stateLogPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 32 * 1024,
            FileOptions.SequentialScan);
        await JsonSerializer.SerializeAsync(stream, state, SerializerOptions, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static ImageAcquisitionState BuildState(
        string sourcePath,
        string destinationPath,
        long sourceSizeBytes,
        int chunkSizeBytes,
        long bytesWritten,
        DateTimeOffset startedUtc,
        string status,
        ImageReadErrorPolicy readErrorPolicy,
        int readErrorChunks,
        long zeroFilledBytes,
        string? sourceSha256Hex,
        string? destinationSha256Hex,
        string? error)
    {
        return new ImageAcquisitionState
        {
            SourcePath = sourcePath,
            DestinationImagePath = destinationPath,
            SourceSizeBytes = sourceSizeBytes,
            ChunkSizeBytes = chunkSizeBytes,
            BytesWritten = bytesWritten,
            StartedUtc = startedUtc,
            UpdatedUtc = DateTimeOffset.UtcNow,
            Status = status,
            ReadErrorPolicy = readErrorPolicy,
            ReadErrorChunks = readErrorChunks,
            ZeroFilledBytes = zeroFilledBytes,
            SourceSha256Hex = sourceSha256Hex,
            DestinationSha256Hex = destinationSha256Hex,
            Error = error,
        };
    }

    private static double Percent(long bytesWritten, long totalBytes)
    {
        if (totalBytes <= 0)
        {
            return 0;
        }

        var percent = (bytesWritten / (double)totalBytes) * 100.0;
        return Math.Clamp(percent, 0, 100);
    }

    private sealed record ImageAcquisitionState
    {
        public string SourcePath { get; init; } = string.Empty;
        public string DestinationImagePath { get; init; } = string.Empty;
        public long SourceSizeBytes { get; init; }
        public int ChunkSizeBytes { get; init; }
        public long BytesWritten { get; init; }
        public DateTimeOffset StartedUtc { get; init; }
        public DateTimeOffset UpdatedUtc { get; init; }
        public string Status { get; init; } = string.Empty;
        public ImageReadErrorPolicy ReadErrorPolicy { get; init; } = ImageReadErrorPolicy.FailFast;
        public int ReadErrorChunks { get; init; }
        public long ZeroFilledBytes { get; init; }
        public string? SourceSha256Hex { get; init; }
        public string? DestinationSha256Hex { get; init; }
        public string? Error { get; init; }
    }
}
