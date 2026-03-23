using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Persistence;
using Microsoft.Data.Sqlite;

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

    [Fact]
    public async Task AppliesRetentionPolicyAndCompactsDatabase()
    {
        var dbDirectory = Path.Combine(Path.GetTempPath(), "fr-tests-db", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dbDirectory);
        var dbPath = Path.Combine(dbDirectory, "sessions.db");

        var store = new SqliteSessionStore(dbPath);
        await store.EnsureCreatedAsync(CancellationToken.None);

        var source = new SourceCandidate(
            Id: "volume-d",
            Kind: RecoverySourceKind.Volume,
            DisplayName: "D",
            DevicePath: "\\\\.\\D:",
            FileSystem: "NTFS",
            SizeBytes: 100,
            SectorSizeBytes: 512,
            DiskIndex: 1,
            VolumeIdentity: "VOL-D",
            SourcePath: "D:\\",
            ReadOnlyEnforced: true);

        var destination = Path.Combine(dbDirectory, "destination");
        Directory.CreateDirectory(destination);

        var sessionIds = new List<Guid>();
        for (var i = 0; i < 5; i++)
        {
            var sessionId = await store.CreateSessionAsync(source, destination, ScanMode.Quick, CancellationToken.None);
            sessionIds.Add(sessionId);
            await store.ReplaceQuickScanCandidatesAsync(
                sessionId,
                new[] { BuildCandidate(ordinal: 0, recordNumber: checked((uint)(100 + i))) },
                CancellationToken.None);
        }

        await SetSessionUpdatedUtcAsync(dbPath, sessionIds[0], DateTimeOffset.UtcNow.AddDays(-120));
        await SetSessionUpdatedUtcAsync(dbPath, sessionIds[1], DateTimeOffset.UtcNow.AddDays(-40));
        await SetSessionUpdatedUtcAsync(dbPath, sessionIds[2], DateTimeOffset.UtcNow.AddDays(-3));
        await SetSessionUpdatedUtcAsync(dbPath, sessionIds[3], DateTimeOffset.UtcNow.AddDays(-2));
        await SetSessionUpdatedUtcAsync(dbPath, sessionIds[4], DateTimeOffset.UtcNow.AddDays(-1));

        var maintenance = await store.ApplyRetentionPolicyAsync(
            maxSessionAge: TimeSpan.FromDays(30),
            maxSessionCount: 2,
            compactDatabase: true,
            cancellationToken: CancellationToken.None);

        Assert.Equal(2, maintenance.DeletedByAge);
        Assert.Equal(1, maintenance.DeletedByOverflow);
        Assert.Equal(2, maintenance.RemainingSessions);
        Assert.True(maintenance.Compacted);

        var sessions = await store.GetRecentSessionsAsync(10, CancellationToken.None);
        Assert.Equal(2, sessions.Count);
        Assert.Equal(sessionIds[4], sessions[0].SessionId);
        Assert.Equal(sessionIds[3], sessions[1].SessionId);

        var latestCandidates = await store.GetQuickScanCandidatesAsync(sessionIds[4], 10, CancellationToken.None);
        Assert.Single(latestCandidates);
        var secondLatestCandidates = await store.GetQuickScanCandidatesAsync(sessionIds[3], 10, CancellationToken.None);
        Assert.Single(secondLatestCandidates);

        var removedCandidatesByAge = await store.GetQuickScanCandidatesAsync(sessionIds[1], 10, CancellationToken.None);
        Assert.Empty(removedCandidatesByAge);
        var removedCandidatesByCount = await store.GetQuickScanCandidatesAsync(sessionIds[2], 10, CancellationToken.None);
        Assert.Empty(removedCandidatesByCount);
    }

    private static QuickScanCandidateRecord BuildCandidate(int ordinal, uint recordNumber)
    {
        return new QuickScanCandidateRecord(
            Ordinal: ordinal,
            RecordNumber: recordNumber,
            Deleted: true,
            Directory: false,
            NonResidentData: true,
            Name: $"candidate-{recordNumber}.bin",
            OriginalPath: $@"Recovered\candidate-{recordNumber}.bin",
            ParentRecordNumber: null,
            ConfidenceTier: "Medium",
            ConfidenceReason: "Test candidate",
            CandidateStatus: RecoveryCandidateStatus.Partial);
    }

    private static async Task SetSessionUpdatedUtcAsync(string dbPath, Guid sessionId, DateTimeOffset updatedUtc)
    {
        await using var connection = new SqliteConnection($"Data Source={dbPath}");
        await connection.OpenAsync(CancellationToken.None);

        var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE sessions
            SET updated_utc = $updated_utc
            WHERE session_id = $session_id;
            """;
        command.Parameters.AddWithValue("$updated_utc", updatedUtc.ToString("O"));
        command.Parameters.AddWithValue("$session_id", sessionId.ToString("D"));

        await command.ExecuteNonQueryAsync(CancellationToken.None);
    }
}
