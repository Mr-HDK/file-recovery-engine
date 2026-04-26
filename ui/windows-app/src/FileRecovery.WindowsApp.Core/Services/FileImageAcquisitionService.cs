using FileRecovery.WindowsApp.Core.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class FileImageAcquisitionService : IImageAcquisitionService
{
    private const int MinChunkSizeBytes = 64 * 1024;
    private const int DefaultConstrainedNetworkChunkSizeBytes = 512 * 1024;
    private readonly Func<string, int, Stream> _sourceStreamFactory;
    private readonly IRemoteAgentRuntime _remoteAgentRuntime;

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };
    private static readonly JsonSerializerOptions JsonLineSerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    public FileImageAcquisitionService()
        : this(null, null)
    {
    }

    public FileImageAcquisitionService(
        Func<string, int, Stream>? sourceStreamFactory,
        IRemoteAgentRuntime? remoteAgentRuntime = null)
    {
        _sourceStreamFactory = sourceStreamFactory ?? OpenDefaultSourceStream;
        _remoteAgentRuntime = remoteAgentRuntime ?? new HybridRemoteAgentRuntime();
    }

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
        if (request.ConstrainedNetworkChunkSizeBytes < MinChunkSizeBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                $"Constrained network chunk size must be at least {MinChunkSizeBytes} bytes.");
        }
        if (request.MaxNetworkThroughputBytesPerSecond.HasValue
            && request.MaxNetworkThroughputBytesPerSecond.Value <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "Max network throughput must be positive when specified.");
        }
        if (request.RemoteAgentMode == RemoteAgentMode.Required
            && string.IsNullOrWhiteSpace(request.RemoteAgentEndpoint))
        {
            throw new InvalidOperationException(
                "Remote agent endpoint is required when remote agent mode is set to Required.");
        }

        var sourcePath = NormalizeSourcePath(request.SourcePath);
        var destinationPath = Path.GetFullPath(request.DestinationImagePath);
        if (string.Equals(sourcePath, destinationPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Source and destination image paths must be different.");
        }

        var stateLogPath = string.IsNullOrWhiteSpace(request.StateLogPath)
            ? destinationPath + ".acquisition.json"
            : Path.GetFullPath(request.StateLogPath);
        var isNetworkSource = request.SourceIsNetwork || IsLikelyNetworkPath(sourcePath);
        var constrainedNetworkIo = isNetworkSource && request.EnableConstrainedNetworkIo;
        var effectiveChunkSizeBytes = AlignChunkSize(
            constrainedNetworkIo
                ? Math.Min(request.ChunkSizeBytes, request.ConstrainedNetworkChunkSizeBytes)
                : request.ChunkSizeBytes);
        if (effectiveChunkSizeBytes <= 0)
        {
            effectiveChunkSizeBytes = AlignChunkSize(DefaultConstrainedNetworkChunkSizeBytes);
        }
        var custodyLogPath = isNetworkSource
            ? (string.IsNullOrWhiteSpace(request.ChainOfCustodyLogPath)
                ? stateLogPath + ".custody.jsonl"
                : Path.GetFullPath(request.ChainOfCustodyLogPath))
            : null;
        var remoteExecutionStatus = RemoteExecutionStatus.NotRequested;
        var remoteExecutionErrorCode = RemoteExecutionErrorCode.None;
        string? remoteExecutionMessage = null;
        string? remoteExecutionIntegrityHash = null;

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
        if (isNetworkSource && custodyLogPath is not null)
        {
            var custodyDirectory = Path.GetDirectoryName(custodyLogPath);
            if (!string.IsNullOrWhiteSpace(custodyDirectory))
            {
                Directory.CreateDirectory(custodyDirectory);
            }
        }

        if (request.RemoteAgentMode != RemoteAgentMode.Disabled)
        {
            var remoteExecution = await ExecuteRemoteAcquisitionHandshakeAsync(
                request,
                sourcePath,
                destinationPath,
                effectiveChunkSizeBytes,
                cancellationToken);
            remoteExecutionStatus = remoteExecution.Status;
            remoteExecutionErrorCode = remoteExecution.ErrorCode;
            remoteExecutionMessage = remoteExecution.Message;
            remoteExecutionIntegrityHash = remoteExecution.Integrity?.RequestHashHex;

            if (remoteExecutionStatus != RemoteExecutionStatus.Succeeded)
            {
                throw new InvalidOperationException(
                    $"Remote agent handshake failed: {remoteExecution.Message} ({remoteExecution.ErrorCode}).");
            }
        }

        if (!File.Exists(sourcePath))
        {
            throw new FileNotFoundException("Source path not found.", sourcePath);
        }

        await using var sourceStream = _sourceStreamFactory(sourcePath, effectiveChunkSizeBytes);
        if (!sourceStream.CanRead)
        {
            throw new InvalidOperationException("Source stream is not readable.");
        }
        if (!sourceStream.CanSeek)
        {
            throw new InvalidOperationException("Source stream must be seekable.");
        }

        var sourceSizeBytes = sourceStream.Length;
        var startedUtc = DateTimeOffset.UtcNow;
        var bytesWritten = 0L;
        var resumed = false;
        var sourceHashHex = string.Empty;
        var destinationHashHex = string.Empty;
        var readErrorChunks = 0;
        var zeroFilledBytes = 0L;
        var unreadableRanges = new List<UnreadableRange>();
        string? unreadableRangesManifestPath = null;

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
                effectiveChunkSizeBytes);

        var networkCheckpointCount = 0;
        var custodyState = await InitializeCustodyStateAsync(custodyLogPath, cancellationToken);

        if (canResume)
        {
            startedUtc = checkpoint!.StartedUtc;
            var destinationLength = new FileInfo(destinationPath).Length;
            bytesWritten = Math.Min(Math.Min(destinationLength, checkpoint.BytesWritten), sourceSizeBytes);
            resumed = bytesWritten > 0;
            readErrorChunks = checkpoint.ReadErrorChunks;
            zeroFilledBytes = checkpoint.ZeroFilledBytes;
            networkCheckpointCount = checkpoint.NetworkCheckpointCount;
            if (isNetworkSource && custodyState is not null)
            {
                custodyState.Sequence = Math.Max(custodyState.Sequence, networkCheckpointCount);
            }
        }
        var runStartBytesWritten = bytesWritten;

        await WriteStateAsync(
            stateLogPath,
            BuildState(
                sourcePath,
                destinationPath,
                sourceSizeBytes,
                effectiveChunkSizeBytes,
                bytesWritten,
                startedUtc,
                status: "in_progress",
                readErrorPolicy: request.ReadErrorPolicy,
                readErrorChunks: readErrorChunks,
                zeroFilledBytes: zeroFilledBytes,
                sourceSha256Hex: null,
                destinationSha256Hex: null,
                error: null,
                sourceIsNetwork: isNetworkSource,
                constrainedNetworkIo: constrainedNetworkIo,
                maxNetworkThroughputBytesPerSecond: request.MaxNetworkThroughputBytesPerSecond,
                remoteAgentMode: request.RemoteAgentMode,
                remoteAgentEndpoint: request.RemoteAgentEndpoint,
                remoteExecutionStatus: remoteExecutionStatus,
                remoteExecutionErrorCode: remoteExecutionErrorCode,
                remoteExecutionMessage: remoteExecutionMessage,
                remoteExecutionIntegrityHash: remoteExecutionIntegrityHash,
                networkCheckpointCount: networkCheckpointCount),
            cancellationToken);

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var lastCheckpointWrite = TimeSpan.Zero;
        var bytesAtLastSample = bytesWritten;
        var lastSampleElapsed = TimeSpan.Zero;
        using var sourceHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        if (isNetworkSource && custodyState is not null)
        {
            custodyState = await AppendCustodyEventAsync(
                custodyLogPath!,
                custodyState,
                eventName: "network_acquisition_started",
                payload: new
                {
                    source_path = sourcePath,
                    destination_path = destinationPath,
                    resumed,
                    chunk_size_bytes = effectiveChunkSizeBytes,
                    constrained_network_io = constrainedNetworkIo,
                    max_network_throughput_bps = request.MaxNetworkThroughputBytesPerSecond,
                    remote_agent_mode = request.RemoteAgentMode.ToString(),
                    remote_agent_endpoint = request.RemoteAgentEndpoint,
                },
                cancellationToken);
        }

        try
        {
            if (resumed)
            {
                await VerifyAndHashResumePrefixAsync(
                    sourceStream,
                    destinationPath,
                    bytesWritten,
                    effectiveChunkSizeBytes,
                    sourceHash,
                    cancellationToken);
            }

            await using (
                var destinationStream = new FileStream(
                    destinationPath,
                    resumed ? FileMode.Open : FileMode.Create,
                    FileAccess.Write,
                    FileShare.None,
                    effectiveChunkSizeBytes,
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

                var buffer = new byte[effectiveChunkSizeBytes];
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

                    var rangeStartOffset = bytesWritten;
                    await destinationStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    sourceHash.AppendData(buffer, 0, read);
                    bytesWritten += read;
                    if (zeroFilled)
                    {
                        readErrorChunks++;
                        zeroFilledBytes += read;
                        unreadableRanges.Add(new UnreadableRange(
                            OffsetBytes: rangeStartOffset,
                            LengthBytes: read,
                            Reason: "source-read-io-error"));
                    }
                    if (isNetworkSource
                        && request.MaxNetworkThroughputBytesPerSecond.HasValue
                        && request.MaxNetworkThroughputBytesPerSecond.Value > 0)
                    {
                        await ApplyNetworkThroughputThrottleAsync(
                            bytesWritten - runStartBytesWritten,
                            request.MaxNetworkThroughputBytesPerSecond.Value,
                            stopwatch.Elapsed,
                            cancellationToken);
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
                        if (isNetworkSource)
                        {
                            networkCheckpointCount++;
                        }
                        await WriteStateAsync(
                            stateLogPath,
                            BuildState(
                                sourcePath,
                                destinationPath,
                                sourceSizeBytes,
                                effectiveChunkSizeBytes,
                                bytesWritten,
                                startedUtc,
                                status: "in_progress",
                                readErrorPolicy: request.ReadErrorPolicy,
                                readErrorChunks: readErrorChunks,
                                zeroFilledBytes: zeroFilledBytes,
                                sourceSha256Hex: null,
                                destinationSha256Hex: null,
                                error: null,
                                sourceIsNetwork: isNetworkSource,
                                constrainedNetworkIo: constrainedNetworkIo,
                                maxNetworkThroughputBytesPerSecond: request.MaxNetworkThroughputBytesPerSecond,
                                remoteAgentMode: request.RemoteAgentMode,
                                remoteAgentEndpoint: request.RemoteAgentEndpoint,
                                remoteExecutionStatus: remoteExecutionStatus,
                                remoteExecutionErrorCode: remoteExecutionErrorCode,
                                remoteExecutionMessage: remoteExecutionMessage,
                                remoteExecutionIntegrityHash: remoteExecutionIntegrityHash,
                                networkCheckpointCount: networkCheckpointCount),
                            cancellationToken);
                        if (isNetworkSource && custodyState is not null)
                        {
                            custodyState = await AppendCustodyEventAsync(
                                custodyLogPath!,
                                custodyState,
                                eventName: "network_transfer_checkpoint",
                                payload: new
                                {
                                    bytes_written = bytesWritten,
                                    read_error_chunks = readErrorChunks,
                                    zero_filled_bytes = zeroFilledBytes,
                                    checkpoint = networkCheckpointCount,
                                },
                                cancellationToken);
                        }
                        lastCheckpointWrite = elapsed;
                    }

                    bytesAtLastSample = bytesWritten;
                    lastSampleElapsed = elapsed;
                }

                await destinationStream.FlushAsync(cancellationToken);
            }

            sourceHashHex = Convert.ToHexString(sourceHash.GetHashAndReset()).ToLowerInvariant();
            destinationHashHex = await ComputeSha256HexAsync(destinationPath, effectiveChunkSizeBytes, cancellationToken);
            if (!string.Equals(sourceHashHex, destinationHashHex, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Source and destination SHA-256 digests do not match.");
            }

            if (isNetworkSource && custodyState is not null)
            {
                custodyState = await AppendCustodyEventAsync(
                    custodyLogPath!,
                    custodyState,
                    eventName: "network_acquisition_completed",
                    payload: new
                    {
                        bytes_written = bytesWritten,
                        source_sha256 = sourceHashHex,
                        destination_sha256 = destinationHashHex,
                        read_error_chunks = readErrorChunks,
                        zero_filled_bytes = zeroFilledBytes,
                        checkpoints = networkCheckpointCount,
                    },
                    cancellationToken);
            }
            unreadableRangesManifestPath = await WriteUnreadableRangesManifestIfNeededAsync(
                stateLogPath,
                sourcePath,
                destinationPath,
                request.ReadErrorPolicy,
                unreadableRanges,
                cancellationToken);

            var completedState = BuildState(
                sourcePath,
                destinationPath,
                sourceSizeBytes,
                effectiveChunkSizeBytes,
                bytesWritten,
                startedUtc,
                status: "completed",
                readErrorPolicy: request.ReadErrorPolicy,
                readErrorChunks: readErrorChunks,
                zeroFilledBytes: zeroFilledBytes,
                sourceSha256Hex: sourceHashHex,
                destinationSha256Hex: destinationHashHex,
                error: null,
                sourceIsNetwork: isNetworkSource,
                constrainedNetworkIo: constrainedNetworkIo,
                maxNetworkThroughputBytesPerSecond: request.MaxNetworkThroughputBytesPerSecond,
                remoteAgentMode: request.RemoteAgentMode,
                remoteAgentEndpoint: request.RemoteAgentEndpoint,
                remoteExecutionStatus: remoteExecutionStatus,
                remoteExecutionErrorCode: remoteExecutionErrorCode,
                remoteExecutionMessage: remoteExecutionMessage,
                remoteExecutionIntegrityHash: remoteExecutionIntegrityHash,
                networkCheckpointCount: networkCheckpointCount,
                unreadableRangesManifestPath: unreadableRangesManifestPath);
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
                ZeroFilledBytes: zeroFilledBytes,
                SourceIsNetwork: isNetworkSource,
                ConstrainedNetworkIo: constrainedNetworkIo,
                MaxNetworkThroughputBytesPerSecond: request.MaxNetworkThroughputBytesPerSecond,
                RemoteAgentMode: request.RemoteAgentMode,
                RemoteAgentEndpoint: request.RemoteAgentEndpoint,
                RemoteExecutionStatus: remoteExecutionStatus,
                RemoteExecutionErrorCode: remoteExecutionErrorCode,
                RemoteExecutionMessage: remoteExecutionMessage,
                RemoteExecutionIntegrityHash: remoteExecutionIntegrityHash,
                ChainOfCustodyLogPath: custodyLogPath,
                NetworkCheckpointCount: networkCheckpointCount,
                UnreadableRangesManifestPath: unreadableRangesManifestPath);
        }
        catch (OperationCanceledException)
        {
            if (request.RemoteAgentMode != RemoteAgentMode.Disabled)
            {
                remoteExecutionStatus = RemoteExecutionStatus.Canceled;
                remoteExecutionMessage = "Remote operation canceled.";
            }

            if (isNetworkSource && custodyState is not null)
            {
                await AppendCustodyEventAsync(
                    custodyLogPath!,
                    custodyState,
                    eventName: "network_acquisition_canceled",
                    payload: new
                    {
                        bytes_written = bytesWritten,
                        read_error_chunks = readErrorChunks,
                        zero_filled_bytes = zeroFilledBytes,
                    },
                    CancellationToken.None);
            }
            unreadableRangesManifestPath = await WriteUnreadableRangesManifestIfNeededAsync(
                stateLogPath,
                sourcePath,
                destinationPath,
                request.ReadErrorPolicy,
                unreadableRanges,
                CancellationToken.None);
            await WriteStateAsync(
                stateLogPath,
                BuildState(
                    sourcePath,
                    destinationPath,
                    sourceSizeBytes,
                    effectiveChunkSizeBytes,
                    bytesWritten,
                    startedUtc,
                    status: "canceled",
                    readErrorPolicy: request.ReadErrorPolicy,
                    readErrorChunks: readErrorChunks,
                    zeroFilledBytes: zeroFilledBytes,
                    sourceSha256Hex: sourceHashHex,
                    destinationSha256Hex: destinationHashHex,
                    error: "Acquisition canceled.",
                    sourceIsNetwork: isNetworkSource,
                    constrainedNetworkIo: constrainedNetworkIo,
                    maxNetworkThroughputBytesPerSecond: request.MaxNetworkThroughputBytesPerSecond,
                    remoteAgentMode: request.RemoteAgentMode,
                    remoteAgentEndpoint: request.RemoteAgentEndpoint,
                    remoteExecutionStatus: remoteExecutionStatus,
                    remoteExecutionErrorCode: remoteExecutionErrorCode,
                    remoteExecutionMessage: remoteExecutionMessage,
                    remoteExecutionIntegrityHash: remoteExecutionIntegrityHash,
                    networkCheckpointCount: networkCheckpointCount,
                    unreadableRangesManifestPath: unreadableRangesManifestPath),
                CancellationToken.None);
            throw;
        }
        catch (Exception ex)
        {
            if (isNetworkSource && custodyState is not null)
            {
                await AppendCustodyEventAsync(
                    custodyLogPath!,
                    custodyState,
                    eventName: "network_acquisition_failed",
                    payload: new
                    {
                        bytes_written = bytesWritten,
                        read_error_chunks = readErrorChunks,
                        zero_filled_bytes = zeroFilledBytes,
                        error = ex.Message,
                    },
                    CancellationToken.None);
            }
            unreadableRangesManifestPath = await WriteUnreadableRangesManifestIfNeededAsync(
                stateLogPath,
                sourcePath,
                destinationPath,
                request.ReadErrorPolicy,
                unreadableRanges,
                CancellationToken.None);
            await WriteStateAsync(
                stateLogPath,
                BuildState(
                    sourcePath,
                    destinationPath,
                    sourceSizeBytes,
                    effectiveChunkSizeBytes,
                    bytesWritten,
                    startedUtc,
                    status: "failed",
                    readErrorPolicy: request.ReadErrorPolicy,
                    readErrorChunks: readErrorChunks,
                    zeroFilledBytes: zeroFilledBytes,
                    sourceSha256Hex: sourceHashHex,
                    destinationSha256Hex: destinationHashHex,
                    error: ex.Message,
                    sourceIsNetwork: isNetworkSource,
                    constrainedNetworkIo: constrainedNetworkIo,
                    maxNetworkThroughputBytesPerSecond: request.MaxNetworkThroughputBytesPerSecond,
                    remoteAgentMode: request.RemoteAgentMode,
                    remoteAgentEndpoint: request.RemoteAgentEndpoint,
                    remoteExecutionStatus: remoteExecutionStatus,
                    remoteExecutionErrorCode: remoteExecutionErrorCode,
                    remoteExecutionMessage: remoteExecutionMessage,
                    remoteExecutionIntegrityHash: remoteExecutionIntegrityHash,
                    networkCheckpointCount: networkCheckpointCount,
                    unreadableRangesManifestPath: unreadableRangesManifestPath),
                CancellationToken.None);
            throw;
        }
    }

    private async Task<RemoteAgentResponse> ExecuteRemoteAcquisitionHandshakeAsync(
        ImageAcquisitionRequest request,
        string sourcePath,
        string destinationPath,
        int chunkSizeBytes,
        CancellationToken cancellationToken)
    {
        var endpoint = request.RemoteAgentEndpoint?.Trim() ?? string.Empty;
        if (request.RemoteAgentMode == RemoteAgentMode.Required && string.IsNullOrWhiteSpace(endpoint))
        {
            return new RemoteAgentResponse(
                RequestId: Guid.NewGuid(),
                Status: RemoteExecutionStatus.InvalidRequest,
                ErrorCode: RemoteExecutionErrorCode.EndpointRequired,
                Message: "Remote agent endpoint is required.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: new RemoteAgentIntegrityMetadata(
                    RequestHashHex: string.Empty,
                    PayloadHashHex: null,
                    CheckpointHashHex: null));
        }

        var payloadHash = ComputeDeterministicHash(
            $"{sourcePath}|{destinationPath}|{chunkSizeBytes}|{request.AllowResume}|{request.ReadErrorPolicy}");
        var requestHash = ComputeDeterministicHash(
            $"{endpoint}|{request.RemoteAgentMode}|{request.SourceIsNetwork}|{payloadHash}");
        var agentRequest = new RemoteAgentRequest(
            RequestId: Guid.NewGuid(),
            Endpoint: endpoint,
            Operation: RemoteAgentOperationKind.Acquisition,
            RequestedUtc: DateTimeOffset.UtcNow,
            Integrity: new RemoteAgentIntegrityMetadata(
                RequestHashHex: requestHash,
                PayloadHashHex: payloadHash,
                CheckpointHashHex: null));

        var response = await _remoteAgentRuntime.ExecuteAsync(agentRequest, cancellationToken);
        if (response.Status == RemoteExecutionStatus.Succeeded
            && response.RequestId != agentRequest.RequestId)
        {
            return response with
            {
                Status = RemoteExecutionStatus.IntegrityFailure,
                ErrorCode = RemoteExecutionErrorCode.InvalidResponse,
                Message = "Remote execution request id mismatch.",
            };
        }

        if (response.Status == RemoteExecutionStatus.Succeeded
            && (response.Integrity is null
                || !string.Equals(
                    response.Integrity.RequestHashHex,
                    requestHash,
                    StringComparison.OrdinalIgnoreCase)))
        {
            return response with
            {
                Status = RemoteExecutionStatus.IntegrityFailure,
                ErrorCode = RemoteExecutionErrorCode.IntegrityVerificationFailed,
                Message = "Remote execution integrity hash mismatch.",
            };
        }

        return response;
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
        Stream sourceStream,
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
        Stream sourceStream,
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

    private static async Task ApplyNetworkThroughputThrottleAsync(
        long bytesTransferredInCurrentRun,
        long maxThroughputBytesPerSecond,
        TimeSpan elapsed,
        CancellationToken cancellationToken)
    {
        if (bytesTransferredInCurrentRun <= 0 || maxThroughputBytesPerSecond <= 0)
        {
            return;
        }

        var expectedElapsedSeconds = bytesTransferredInCurrentRun / (double)maxThroughputBytesPerSecond;
        var expectedElapsed = TimeSpan.FromSeconds(expectedElapsedSeconds);
        if (expectedElapsed <= elapsed)
        {
            return;
        }

        var delay = expectedElapsed - elapsed;
        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, cancellationToken);
        }
    }

    private static int AlignChunkSize(int chunkSizeBytes)
    {
        if (chunkSizeBytes < MinChunkSizeBytes)
        {
            return MinChunkSizeBytes;
        }

        var remainder = chunkSizeBytes % MinChunkSizeBytes;
        if (remainder == 0)
        {
            return chunkSizeBytes;
        }

        return checked(chunkSizeBytes + (MinChunkSizeBytes - remainder));
    }

    private static Stream OpenDefaultSourceStream(string sourcePath, int chunkSizeBytes)
    {
        return new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            chunkSizeBytes,
            FileOptions.SequentialScan);
    }

    private static bool IsLikelyNetworkPath(string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            return false;
        }

        if (sourcePath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return true;
        }

        try
        {
            var root = Path.GetPathRoot(sourcePath);
            if (string.IsNullOrWhiteSpace(root))
            {
                return false;
            }

            var drive = new DriveInfo(root);
            return drive.DriveType == DriveType.Network;
        }
        catch
        {
            return false;
        }
    }

    private static string NormalizeSourcePath(string sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw new ArgumentException("Source path is required.", nameof(sourcePath));
        }

        var trimmed = sourcePath.Trim();
        if (trimmed.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return trimmed;
        }

        return Path.GetFullPath(trimmed);
    }

    private static async Task<CustodyState?> InitializeCustodyStateAsync(
        string? custodyLogPath,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(custodyLogPath))
        {
            return null;
        }

        if (!File.Exists(custodyLogPath))
        {
            return new CustodyState();
        }

        var lastRecord = await ReadLastCustodyRecordAsync(custodyLogPath, cancellationToken);
        if (lastRecord is null)
        {
            return new CustodyState();
        }

        return new CustodyState
        {
            Sequence = lastRecord.Value.Sequence,
            PreviousHash = lastRecord.Value.RecordHash,
        };
    }

    private static async Task<CustodyState> AppendCustodyEventAsync(
        string custodyLogPath,
        CustodyState custodyState,
        string eventName,
        object payload,
        CancellationToken cancellationToken)
    {
        var payloadJson = JsonSerializer.Serialize(payload, JsonLineSerializerOptions);
        var timestampUtc = DateTimeOffset.UtcNow;
        var sequence = custodyState.Sequence + 1;
        var previousHash = custodyState.PreviousHash;
        var hashInput = $"{previousHash}|{sequence}|{timestampUtc:O}|{eventName}|{payloadJson}";
        var recordHash = ComputeDeterministicHash(hashInput);

        var record = new
        {
            sequence,
            timestamp_utc = timestampUtc,
            event_name = eventName,
            previous_hash = previousHash,
            payload,
            record_hash = recordHash,
        };

        var line = JsonSerializer.Serialize(record, JsonLineSerializerOptions) + Environment.NewLine;
        await File.AppendAllTextAsync(custodyLogPath, line, cancellationToken);

        custodyState.Sequence = sequence;
        custodyState.PreviousHash = recordHash;
        return custodyState;
    }

    private static string ComputeDeterministicHash(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async Task<(int Sequence, string RecordHash)?> ReadLastCustodyRecordAsync(
        string custodyLogPath,
        CancellationToken cancellationToken)
    {
        string? lastLine = null;
        await using var stream = new FileStream(
            custodyLogPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: 16 * 1024,
            FileOptions.SequentialScan);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        while (!reader.EndOfStream)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(cancellationToken);
            if (!string.IsNullOrWhiteSpace(line))
            {
                lastLine = line;
            }
        }

        if (string.IsNullOrWhiteSpace(lastLine))
        {
            return null;
        }

        using var doc = JsonDocument.Parse(lastLine);
        if (!doc.RootElement.TryGetProperty("sequence", out var sequenceElement))
        {
            return null;
        }
        if (!doc.RootElement.TryGetProperty("record_hash", out var recordHashElement))
        {
            return null;
        }
        var sequence = sequenceElement.GetInt32();
        var recordHash = recordHashElement.GetString();
        if (string.IsNullOrWhiteSpace(recordHash))
        {
            return null;
        }

        return (sequence, recordHash);
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

    private static async Task<string?> WriteUnreadableRangesManifestIfNeededAsync(
        string stateLogPath,
        string sourcePath,
        string destinationPath,
        ImageReadErrorPolicy readErrorPolicy,
        IReadOnlyList<UnreadableRange> unreadableRanges,
        CancellationToken cancellationToken)
    {
        if (unreadableRanges.Count == 0)
        {
            return null;
        }

        var manifestPath = BuildUnreadableRangesManifestPath(stateLogPath);
        var manifest = new UnreadableRangesManifest(
            SourcePath: sourcePath,
            DestinationImagePath: destinationPath,
            GeneratedUtc: DateTimeOffset.UtcNow,
            ReadErrorPolicy: readErrorPolicy,
            RangeCount: unreadableRanges.Count,
            ZeroFilledBytes: unreadableRanges.Aggregate(0L, (total, range) => total + range.LengthBytes),
            Ranges: unreadableRanges
                .Select((range, index) => new UnreadableRangeManifestEntry(
                    Sequence: index + 1,
                    OffsetBytes: range.OffsetBytes,
                    LengthBytes: range.LengthBytes,
                    Reason: range.Reason))
                .ToArray());

        await using var stream = new FileStream(
            manifestPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 32 * 1024,
            FileOptions.SequentialScan);
        await JsonSerializer.SerializeAsync(stream, manifest, SerializerOptions, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        return manifestPath;
    }

    private static string BuildUnreadableRangesManifestPath(string stateLogPath)
    {
        return stateLogPath + ".unreadable-ranges.json";
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
        string? error,
        bool sourceIsNetwork,
        bool constrainedNetworkIo,
        long? maxNetworkThroughputBytesPerSecond,
        RemoteAgentMode remoteAgentMode,
        string? remoteAgentEndpoint,
        RemoteExecutionStatus remoteExecutionStatus,
        RemoteExecutionErrorCode remoteExecutionErrorCode,
        string? remoteExecutionMessage,
        string? remoteExecutionIntegrityHash,
        int networkCheckpointCount,
        string? unreadableRangesManifestPath = null)
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
            SourceIsNetwork = sourceIsNetwork,
            ConstrainedNetworkIo = constrainedNetworkIo,
            MaxNetworkThroughputBytesPerSecond = maxNetworkThroughputBytesPerSecond,
            RemoteAgentMode = remoteAgentMode,
            RemoteAgentEndpoint = remoteAgentEndpoint,
            RemoteExecutionStatus = remoteExecutionStatus,
            RemoteExecutionErrorCode = remoteExecutionErrorCode,
            RemoteExecutionMessage = remoteExecutionMessage,
            RemoteExecutionIntegrityHash = remoteExecutionIntegrityHash,
            NetworkCheckpointCount = networkCheckpointCount,
            UnreadableRangesManifestPath = unreadableRangesManifestPath,
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

    private sealed class CustodyState
    {
        public int Sequence { get; set; }
        public string? PreviousHash { get; set; }
    }

    private sealed record UnreadableRange(long OffsetBytes, int LengthBytes, string Reason);

    private sealed record UnreadableRangeManifestEntry(
        int Sequence,
        long OffsetBytes,
        int LengthBytes,
        string Reason);

    private sealed record UnreadableRangesManifest(
        string SourcePath,
        string DestinationImagePath,
        DateTimeOffset GeneratedUtc,
        ImageReadErrorPolicy ReadErrorPolicy,
        int RangeCount,
        long ZeroFilledBytes,
        IReadOnlyList<UnreadableRangeManifestEntry> Ranges);

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
        public bool SourceIsNetwork { get; init; }
        public bool ConstrainedNetworkIo { get; init; }
        public long? MaxNetworkThroughputBytesPerSecond { get; init; }
        public RemoteAgentMode RemoteAgentMode { get; init; } = RemoteAgentMode.Disabled;
        public string? RemoteAgentEndpoint { get; init; }
        public RemoteExecutionStatus RemoteExecutionStatus { get; init; } = RemoteExecutionStatus.NotRequested;
        public RemoteExecutionErrorCode RemoteExecutionErrorCode { get; init; } = RemoteExecutionErrorCode.None;
        public string? RemoteExecutionMessage { get; init; }
        public string? RemoteExecutionIntegrityHash { get; init; }
        public int NetworkCheckpointCount { get; init; }
        public string? UnreadableRangesManifestPath { get; init; }
    }
}
