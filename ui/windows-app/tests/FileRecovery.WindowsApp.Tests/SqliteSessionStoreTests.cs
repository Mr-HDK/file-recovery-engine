using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Persistence;

namespace FileRecovery.WindowsApp.Tests;

public sealed class SqliteSessionStoreTests
{
    [Fact]
    public async Task CreatesAndUpdatesSession()
    {
        var dbDirectory = Path.Combine(Path.GetTempPath(), "fr-tests-db", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dbDirectory);
        var dbPath = Path.Combine(dbDirectory, "sessions.db");

        var store = new SqliteSessionStore(dbPath);
        await store.EnsureCreatedAsync(CancellationToken.None);

        var source = new SourceCandidate(
            Id: "volume-c",
            Kind: RecoverySourceKind.Volume,
            DisplayName: "C",
            DevicePath: "\\\\.\\C:",
            FileSystem: "NTFS",
            SizeBytes: 100,
            SectorSizeBytes: 512,
            DiskIndex: 0,
            VolumeIdentity: "VOL-C",
            SourcePath: "C:\\",
            ReadOnlyEnforced: true);

        var destination = Path.Combine(dbDirectory, "destination");
        Directory.CreateDirectory(destination);

        var sessionId = await store.CreateSessionAsync(source, destination, ScanMode.Quick, CancellationToken.None);
        await store.UpdateStatusAsync(sessionId, "running", "Started", CancellationToken.None);

        var candidates = new[]
        {
            new QuickScanCandidateRecord(
                Ordinal: 0,
                RecordNumber: 42,
                Deleted: true,
                Directory: false,
                NonResidentData: true,
                HasNamedDataStreams: true,
                IsCompressed: true,
                IsSparse: false,
                IsEncrypted: false,
                Name: "report.txt",
                OriginalPath: @"Docs\report.txt",
                ParentRecordNumber: 5,
                ConfidenceTier: "Very high",
                ConfidenceReason: "Score 88. MFT metadata present; Original name/path reconstructed",
                CandidateStatus: RecoveryCandidateStatus.Full),
            new QuickScanCandidateRecord(
                Ordinal: 1,
                RecordNumber: 5,
                Deleted: false,
                Directory: true,
                NonResidentData: false,
                HasNamedDataStreams: false,
                IsCompressed: false,
                IsSparse: true,
                IsEncrypted: true,
                Name: "Docs",
                OriginalPath: "Docs",
                ParentRecordNumber: null,
                ConfidenceTier: "Low",
                ConfidenceReason: "Score 35. Carve-only candidate confidence cap",
                CandidateStatus: RecoveryCandidateStatus.Invalid),
        };
        await store.ReplaceQuickScanCandidatesAsync(sessionId, candidates, CancellationToken.None);

        var sessions = await store.GetRecentSessionsAsync(10, CancellationToken.None);
        var record = Assert.Single(sessions);

        Assert.Equal(sessionId, record.SessionId);
        Assert.Equal("running", record.Status);
        Assert.Equal("Started", record.Notes);

        var persistedCandidates = await store.GetQuickScanCandidatesAsync(sessionId, 10, CancellationToken.None);
        Assert.Equal(2, persistedCandidates.Count);
        Assert.Equal((uint)42, persistedCandidates[0].RecordNumber);
        Assert.True(persistedCandidates[0].Deleted);
        Assert.True(persistedCandidates[0].HasNamedDataStreams);
        Assert.True(persistedCandidates[0].IsCompressed);
        Assert.False(persistedCandidates[0].IsEncrypted);
        Assert.Equal(@"Docs\report.txt", persistedCandidates[0].OriginalPath);
        Assert.Equal("Very high", persistedCandidates[0].ConfidenceTier);
        Assert.Contains("Score 88", persistedCandidates[0].ConfidenceReason);
        Assert.Equal(RecoveryCandidateStatus.Full, persistedCandidates[0].CandidateStatus);
        Assert.True(persistedCandidates[1].IsSparse);
        Assert.True(persistedCandidates[1].IsEncrypted);
        Assert.Equal(RecoveryCandidateStatus.Invalid, persistedCandidates[1].CandidateStatus);
        Assert.Null(persistedCandidates[0].RecoveryDiagnostics);
        Assert.Null(persistedCandidates[0].LastRecoveryStatusCode);

        await store.ReplaceQuickScanCandidatesAsync(sessionId, new[]
        {
            new QuickScanCandidateRecord(
                Ordinal: 0,
                RecordNumber: 99,
                Deleted: false,
                Directory: false,
                NonResidentData: false,
                Name: "single.bin",
                OriginalPath: @"Recovered\single.bin",
                ParentRecordNumber: null,
                ConfidenceTier: "Medium",
                ConfidenceReason: "Score 60. Test reason",
                CandidateStatus: RecoveryCandidateStatus.OverwrittenRisk),
        }, CancellationToken.None);

        var replacedCandidates = await store.GetQuickScanCandidatesAsync(sessionId, 10, CancellationToken.None);
        Assert.Single(replacedCandidates);
        Assert.Equal((uint)99, replacedCandidates[0].RecordNumber);
        Assert.Equal("Medium", replacedCandidates[0].ConfidenceTier);
        Assert.Equal("Score 60. Test reason", replacedCandidates[0].ConfidenceReason);
        Assert.Equal(RecoveryCandidateStatus.OverwrittenRisk, replacedCandidates[0].CandidateStatus);

        var recoveryStamp = DateTimeOffset.UtcNow;
        await store.UpdateQuickScanCandidateRecoveryAsync(
            sessionId,
            ordinal: 0,
            candidateStatus: RecoveryCandidateStatus.Partial,
            lastRecoveryStatusCode: 45,
            lastRecoveryDiagnosticsFlags: 0x0241,
            lastRecoveredBytes: 128,
            lastRecoveryPartial: true,
            recoveryDiagnostics: "Compressed NTFS attribute present; Compressed attribute not exported",
            lastRecoveryUtc: recoveryStamp,
            cancellationToken: CancellationToken.None);

        var updatedCandidates = await store.GetQuickScanCandidatesAsync(sessionId, 10, CancellationToken.None);
        Assert.Single(updatedCandidates);
        Assert.Equal(RecoveryCandidateStatus.Partial, updatedCandidates[0].CandidateStatus);
        Assert.Equal(45, updatedCandidates[0].LastRecoveryStatusCode);
        Assert.Equal((uint)0x0241, updatedCandidates[0].LastRecoveryDiagnosticsFlags);
        Assert.Equal((ulong)128, updatedCandidates[0].LastRecoveredBytes);
        Assert.True(updatedCandidates[0].LastRecoveryPartial);
        Assert.Contains("Compressed", updatedCandidates[0].RecoveryDiagnostics);
        Assert.True(updatedCandidates[0].LastRecoveryUtc.HasValue);
    }
}
