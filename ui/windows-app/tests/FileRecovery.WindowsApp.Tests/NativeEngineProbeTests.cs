using FileRecovery.WindowsApp.Core.Engine;
using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Tests;

public sealed class NativeEngineProbeTests
{
    [Fact]
    public void ProbeSourceReadOnlyReturnsDeterministicStatus()
    {
        var result = NativeEngineProbe.ProbeSourceReadOnly(@"\\.\PhysicalDrive0", RecoverySourceKind.PhysicalDisk);

        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        if (!result.EngineAvailable)
        {
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
            Assert.False(result.OpenedReadOnly);
        }
        else
        {
            Assert.InRange(result.StatusCode, 0, 16);
        }
    }

    [Fact]
    public void OpenReadOnlySessionReturnsDeterministicStatus()
    {
        var result = NativeEngineProbe.OpenSourceReadOnlySession(@"\\.\PhysicalDrive0", RecoverySourceKind.PhysicalDisk);

        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        if (!result.EngineAvailable)
        {
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
            Assert.False(result.Opened);
            Assert.Equal(0UL, result.SessionId);
        }
        else
        {
            Assert.InRange(result.StatusCode, 0, 16);
        }
    }

    [Fact]
    public void ReadChunkWithoutEngineReturnsUnavailableStatus()
    {
        var buffer = new byte[1024];
        var result = NativeEngineProbe.ReadSourceSessionChunk(1234, 0, buffer);

        if (!result.EngineAvailable)
        {
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
            Assert.False(result.Success);
            Assert.Equal(0U, result.BytesRead);
        }
        else
        {
            Assert.InRange(result.StatusCode, 0, 20);
        }
    }

    [Fact]
    public void ProbeNtfsBootFromSessionReturnsDeterministicStatus()
    {
        var result = NativeEngineProbe.ProbeNtfsBootFromSession(987654321);

        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        if (!result.EngineAvailable)
        {
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
            Assert.False(result.Success);
            Assert.Null(result.Metadata);
        }
        else
        {
            Assert.Contains(result.StatusCode, new[] { 0, 20, 30, 31, 32, 33, 10, 11, 12, 13, 14, 15, 16 });
        }
    }

    [Fact]
    public void QuickScanNtfsFromSessionReturnsDeterministicStatus()
    {
        var result = NativeEngineProbe.QuickScanNtfsFromSession(987654321, maxRecords: 64);

        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        if (!result.EngineAvailable)
        {
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
            Assert.False(result.Success);
            Assert.Equal(0U, result.ParsedRecords);
        }
        else
        {
            Assert.Contains(result.StatusCode, new[] { 0, 20, 30, 31, 32, 33, 10, 11, 12, 13, 14, 15, 16 });
        }
    }

    [Fact]
    public void QuickScanCandidatesFromSessionReturnsDeterministicStatus()
    {
        var result = NativeEngineProbe.GetNtfsQuickScanCandidatesFromSession(987654321, maxRecords: 64, candidateCapacity: 32);

        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        if (!result.EngineAvailable)
        {
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
            Assert.False(result.Success);
            Assert.Empty(result.Candidates);
        }
        else
        {
            Assert.Contains(result.StatusCode, new[] { 0, 20, 30, 31, 32, 33, 10, 11, 12, 13, 14, 15, 16 });
        }
    }

    [Fact]
    public void RecoverNtfsCandidateToFileReturnsDeterministicStatus()
    {
        var tempPath = Path.Combine(Path.GetTempPath(), "fr-recover", Guid.NewGuid().ToString("N"), "candidate.bin");
        var result = NativeEngineProbe.RecoverNtfsCandidateToFile(987654321, 1, tempPath);

        Assert.False(string.IsNullOrWhiteSpace(result.Message));

        if (!result.EngineAvailable)
        {
            Assert.Contains(result.StatusCode, new[] { -100, -101 });
            Assert.False(result.Success);
            Assert.Equal(0UL, result.BytesWritten);
            Assert.Equal(0U, result.DiagnosticsFlags);
        }
        else
        {
            Assert.Contains(result.StatusCode, new[] { 0, 20, 30, 31, 32, 33, 41, 42, 43, 44, 45, 46, 47, 10, 11, 12, 13, 14, 15, 16 });
        }

        Assert.False(string.IsNullOrWhiteSpace(result.DiagnosticsSummary));
    }
}
