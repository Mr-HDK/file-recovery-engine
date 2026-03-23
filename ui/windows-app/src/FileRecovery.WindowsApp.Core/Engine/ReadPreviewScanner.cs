using FileRecovery.WindowsApp.Core.Models;
using System.Diagnostics;

namespace FileRecovery.WindowsApp.Core.Engine;

public sealed record ReadPreviewProgress(
    ulong BytesRead,
    ulong TargetBytes,
    int ChunksRead,
    double ThroughputMiBPerSec
);

public sealed record ReadPreviewResult(
    bool Succeeded,
    bool Canceled,
    ulong BytesRead,
    int ChunksRead,
    string Message,
    int StatusCode
);

public sealed class ReadPreviewScanner
{
    public async Task<ReadPreviewResult> RunAsync(
        SourceCandidate source,
        ulong maxBytes,
        int chunkSize,
        CancellationToken cancellationToken,
        IProgress<ReadPreviewProgress>? progress = null)
    {
        if (chunkSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize), "Chunk size must be greater than zero.");
        }

        var sourcePath = ResolveSourcePath(source);
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            return new ReadPreviewResult(false, false, 0, 0, "Source path unavailable for preview read.", -1);
        }

        var open = NativeEngineProbe.OpenSourceReadOnlySession(sourcePath, source.Kind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new ReadPreviewResult(false, false, 0, 0, open.Message, open.StatusCode);
        }

        var effectiveChunkSize = AlignChunkSize(chunkSize, open.AlignmentBytes);

        var targetBytes = open.SizeBytes > 0 ? Math.Min(maxBytes, open.SizeBytes) : maxBytes;
        if (targetBytes == 0)
        {
            targetBytes = (ulong)effectiveChunkSize;
        }

        if (open.AlignmentBytes > 0)
        {
            var alignment = open.AlignmentBytes;
            targetBytes = (targetBytes / alignment) * alignment;
            if (targetBytes == 0)
            {
                targetBytes = alignment;
            }
        }

        var buffer = new byte[effectiveChunkSize];
        ulong offset = 0;
        var chunks = 0;
        var stopwatch = Stopwatch.StartNew();

        try
        {
            while (offset < targetBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var readLength = buffer.Length;
                if (open.AlignmentBytes == 0)
                {
                    var remaining = targetBytes - offset;
                    if (remaining < (ulong)readLength)
                    {
                        readLength = (int)remaining;
                    }
                }

                var readBuffer = readLength == buffer.Length ? buffer : new byte[readLength];
                var read = NativeEngineProbe.ReadSourceSessionChunk(open.SessionId, offset, readBuffer);
                if (!read.EngineAvailable || !read.Success)
                {
                    return new ReadPreviewResult(false, false, offset, chunks, read.Message, read.StatusCode);
                }

                if (read.BytesRead == 0)
                {
                    break;
                }

                offset += read.BytesRead;
                chunks += 1;

                var throughputMiBPerSec = offset / Math.Max(stopwatch.Elapsed.TotalSeconds, 0.001) / (1024.0 * 1024.0);
                progress?.Report(new ReadPreviewProgress(offset, targetBytes, chunks, throughputMiBPerSec));

                if (read.BytesRead < (uint)readLength)
                {
                    break;
                }

                await Task.Yield();
            }
        }
        catch (OperationCanceledException)
        {
            return new ReadPreviewResult(false, true, offset, chunks, "Preview read canceled.", -300);
        }
        finally
        {
            NativeEngineProbe.CloseSourceSession(open.SessionId);
        }

        return new ReadPreviewResult(true, false, offset, chunks, "Preview read completed.", 0);
    }

    private static string? ResolveSourcePath(SourceCandidate source)
    {
        return source.Kind switch
        {
            RecoverySourceKind.ImageFile => source.SourcePath,
            RecoverySourceKind.Volume => source.DevicePath,
            RecoverySourceKind.Partition => source.DevicePath,
            RecoverySourceKind.PhysicalDisk => source.DevicePath,
            _ => null,
        };
    }

    private static int AlignChunkSize(int chunkSize, uint alignmentBytes)
    {
        if (alignmentBytes == 0)
        {
            return chunkSize;
        }

        var alignment = (int)Math.Min(alignmentBytes, int.MaxValue);
        var remainder = chunkSize % alignment;
        if (remainder == 0)
        {
            return chunkSize;
        }

        return checked(chunkSize + (alignment - remainder));
    }
}
