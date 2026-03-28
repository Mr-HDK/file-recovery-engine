using FileRecovery.WindowsApp.Core.Engine;
using FileRecovery.WindowsApp.Core.Models;
using System.Security.Principal;

namespace FileRecovery.WindowsApp.Tests;

public sealed class HostVssSnapshotRecoveryTests
{
    [Fact]
    [Trait("Category", "HostVssIntegration")]
    public void HostIntegration_EnumeratesSnapshotsAndRunsQuickScanOnSnapshotSource()
    {
        if (!HostIntegrationEnabled())
        {
            return;
        }

        Assert.True(
            IsAdministrator(),
            "Host VSS integration requires elevated PowerShell (Administrator).");

        if (!NativeEngineProbe.IsHealthy())
        {
            Console.WriteLine(
                "Host VSS integration notice: skipping because file_recovery_engine.dll is unavailable in this runtime.");
            return;
        }

        var snapshots = NativeEngineProbe.ListVssSnapshots(snapshotCapacity: 64);
        Assert.True(
            snapshots.EngineAvailable,
            $"VSS listing failed: engine unavailable ({snapshots.StatusCode}).");
        Assert.True(
            snapshots.Success,
            $"VSS listing failed: {snapshots.Message} ({snapshots.StatusCode}).");

        if (snapshots.Snapshots.Count == 0)
        {
            var requireSnapshots = RequireSnapshots();
            var message = "VSS listing returned zero snapshots on this host.";
            if (requireSnapshots)
            {
                Assert.Fail(message);
            }

            Console.WriteLine($"Host VSS integration notice: {message} Test marked inconclusive.");
            return;
        }

        var snapshot = snapshots.Snapshots[0];
        var open = NativeEngineProbe.OpenSourceReadOnlySession(snapshot.SnapshotPath, RecoverySourceKind.Volume);
        Assert.True(
            open.EngineAvailable,
            $"Snapshot source open failed: engine unavailable ({open.StatusCode}).");
        Assert.True(
            open.Opened,
            $"Snapshot source open failed: {open.Message} ({open.StatusCode}). Path={snapshot.SnapshotPath}");

        try
        {
            var preflightBuffer = new byte[GetAlignedBufferLength(open.AlignmentBytes, 4096)];
            var preflight = NativeEngineProbe.ReadSourceSessionChunk(open.SessionId, 0, preflightBuffer);
            Assert.True(
                preflight.Success,
                $"Snapshot preflight read failed: {preflight.Message} ({preflight.StatusCode}).");

            var boot = NativeEngineProbe.ProbeNtfsBootFromSession(open.SessionId);
            Assert.True(
                boot.Success,
                $"Snapshot NTFS boot probe failed: {boot.Message} ({boot.StatusCode}).");

            var quickScan = NativeEngineProbe.QuickScanNtfsFromSession(open.SessionId, maxRecords: 32_768);
            Assert.True(
                quickScan.Success,
                $"Snapshot quick scan failed: {quickScan.Message} ({quickScan.StatusCode}).");

            var candidates = NativeEngineProbe.GetNtfsQuickScanCandidatesFromSession(
                open.SessionId,
                maxRecords: 32_768,
                candidateCapacity: 1024);
            Assert.True(
                candidates.Success,
                $"Snapshot candidate query failed: {candidates.Message} ({candidates.StatusCode}).");

            var recoverable = candidates.Candidates
                .Where(candidate => candidate.Deleted && !candidate.IsDirectory)
                .OrderByDescending(candidate => candidate.RecordNumber)
                .FirstOrDefault();
            if (recoverable is null)
            {
                Console.WriteLine("Host VSS integration notice: no deleted file candidate found in snapshot; recovery probe skipped.");
                return;
            }

            var outputDirectory = Path.Combine(Path.GetTempPath(), "fr-host-vss-integration", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(outputDirectory);
            var outputPath = Path.Combine(outputDirectory, "snapshot-recovery.bin");
            var recovery = NativeEngineProbe.RecoverNtfsCandidateToFile(open.SessionId, recoverable.RecordNumber, outputPath);

            Assert.True(
                recovery.Success || recovery.StatusCode == 41 || recovery.StatusCode == 45,
                $"Snapshot recovery failed: {recovery.Message} ({recovery.StatusCode}).");
            if (recovery.Success)
            {
                Assert.True(File.Exists(outputPath), "Snapshot recovery did not produce an output file.");
            }
        }
        finally
        {
            NativeEngineProbe.CloseSourceSession(open.SessionId);
        }
    }

    private static bool HostIntegrationEnabled()
    {
        var value = Environment.GetEnvironmentVariable("FR_RUN_HOST_INTEGRATION");
        return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase);
    }

    private static bool RequireSnapshots()
    {
        var value = Environment.GetEnvironmentVariable("FR_REQUIRE_VSS_SNAPSHOT");
        return !string.Equals(value, "0", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int GetAlignedBufferLength(uint alignmentBytes, int minimum)
    {
        var alignment = alignmentBytes > 1 ? alignmentBytes : 1;
        var min = Math.Max(minimum, 1);
        var adjusted = ((uint)min + alignment - 1) / alignment * alignment;
        if (adjusted > int.MaxValue)
        {
            return min;
        }

        return (int)adjusted;
    }
}
