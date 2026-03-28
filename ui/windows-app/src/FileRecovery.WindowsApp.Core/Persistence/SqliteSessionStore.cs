using FileRecovery.WindowsApp.Core.Models;
using Microsoft.Data.Sqlite;

namespace FileRecovery.WindowsApp.Core.Persistence;

public sealed class SqliteSessionStore
{
    public SqliteSessionStore(string? databasePath = null)
    {
        DatabasePath = databasePath ?? Path.Combine(FileRecoveryPaths.BaseDirectory, "sessions.db");
    }

    public string DatabasePath { get; }

    public async Task EnsureCreatedAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);

        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText =
            """
            CREATE TABLE IF NOT EXISTS sessions (
              session_id TEXT PRIMARY KEY,
              created_utc TEXT NOT NULL,
              updated_utc TEXT NOT NULL,
              source_id TEXT NOT NULL,
              source_kind INTEGER NOT NULL,
              destination_path TEXT NOT NULL,
              scan_mode INTEGER NOT NULL,
              status TEXT NOT NULL,
              notes TEXT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_utc DESC);

            CREATE TABLE IF NOT EXISTS quick_scan_candidates (
              session_id TEXT NOT NULL,
              ordinal INTEGER NOT NULL,
              record_number INTEGER NOT NULL,
              deleted INTEGER NOT NULL,
              is_ghost_record INTEGER NOT NULL DEFAULT 0,
              is_directory INTEGER NOT NULL,
              non_resident_data INTEGER NOT NULL,
              has_named_data_streams INTEGER NOT NULL DEFAULT 0,
              is_compressed INTEGER NOT NULL DEFAULT 0,
              is_sparse INTEGER NOT NULL DEFAULT 0,
              is_encrypted INTEGER NOT NULL DEFAULT 0,
              name TEXT NULL,
              original_path TEXT NULL,
              parent_record_number INTEGER NULL,
              data_size_bytes INTEGER NULL,
              allocated_size_bytes INTEGER NULL,
              file_attributes INTEGER NULL,
              created_filetime_utc INTEGER NULL,
              modified_filetime_utc INTEGER NULL,
              mft_modified_filetime_utc INTEGER NULL,
              accessed_filetime_utc INTEGER NULL,
              evidence_sources TEXT NOT NULL DEFAULT 'MFT',
              confidence_tier TEXT NOT NULL DEFAULT 'Medium',
              confidence_reason TEXT NOT NULL DEFAULT '',
              candidate_status TEXT NOT NULL DEFAULT 'partial',
              recovery_diagnostics TEXT NULL,
              last_recovery_status_code INTEGER NULL,
              last_recovery_diagnostics_flags INTEGER NULL,
              last_recovery_bytes INTEGER NULL,
              last_recovery_partial INTEGER NULL,
              last_recovery_utc TEXT NULL,
              PRIMARY KEY (session_id, ordinal),
              FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_quick_scan_candidates_session
              ON quick_scan_candidates(session_id, ordinal);
            """;

        await command.ExecuteNonQueryAsync(cancellationToken);
        await EnsureQuickScanCandidateSchemaAsync(connection, cancellationToken);
    }

    public async Task ReplaceQuickScanCandidatesAsync(
        Guid sessionId,
        IReadOnlyList<QuickScanCandidateRecord> candidates,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        {
            var delete = connection.CreateCommand();
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM quick_scan_candidates WHERE session_id = $session_id;";
            delete.Parameters.AddWithValue("$session_id", sessionId.ToString("D"));
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }

        foreach (var candidate in candidates)
        {
            var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText =
                """
                INSERT INTO quick_scan_candidates (
                  session_id,
                  ordinal,
                  record_number,
                  deleted,
                  is_ghost_record,
                  is_directory,
                  non_resident_data,
                  has_named_data_streams,
                  is_compressed,
                  is_sparse,
                  is_encrypted,
                  name,
                  original_path,
                  parent_record_number,
                  data_size_bytes,
                  allocated_size_bytes,
                  file_attributes,
                  created_filetime_utc,
                  modified_filetime_utc,
                  mft_modified_filetime_utc,
                  accessed_filetime_utc,
                  evidence_sources,
                  confidence_tier,
                  confidence_reason,
                  candidate_status,
                  recovery_diagnostics,
                  last_recovery_status_code,
                  last_recovery_diagnostics_flags,
                  last_recovery_bytes,
                  last_recovery_partial,
                  last_recovery_utc
                ) VALUES (
                  $session_id,
                  $ordinal,
                  $record_number,
                  $deleted,
                  $is_ghost_record,
                  $is_directory,
                  $non_resident_data,
                  $has_named_data_streams,
                  $is_compressed,
                  $is_sparse,
                  $is_encrypted,
                  $name,
                  $original_path,
                  $parent_record_number,
                  $data_size_bytes,
                  $allocated_size_bytes,
                  $file_attributes,
                  $created_filetime_utc,
                  $modified_filetime_utc,
                  $mft_modified_filetime_utc,
                  $accessed_filetime_utc,
                  $evidence_sources,
                  $confidence_tier,
                  $confidence_reason,
                  $candidate_status,
                  $recovery_diagnostics,
                  $last_recovery_status_code,
                  $last_recovery_diagnostics_flags,
                  $last_recovery_bytes,
                  $last_recovery_partial,
                  $last_recovery_utc
                );
                """;

            insert.Parameters.AddWithValue("$session_id", sessionId.ToString("D"));
            insert.Parameters.AddWithValue("$ordinal", candidate.Ordinal);
            insert.Parameters.AddWithValue("$record_number", (long)candidate.RecordNumber);
            insert.Parameters.AddWithValue("$deleted", candidate.Deleted ? 1 : 0);
            insert.Parameters.AddWithValue("$is_ghost_record", candidate.IsGhostRecord ? 1 : 0);
            insert.Parameters.AddWithValue("$is_directory", candidate.Directory ? 1 : 0);
            insert.Parameters.AddWithValue("$non_resident_data", candidate.NonResidentData ? 1 : 0);
            insert.Parameters.AddWithValue("$has_named_data_streams", candidate.HasNamedDataStreams ? 1 : 0);
            insert.Parameters.AddWithValue("$is_compressed", candidate.IsCompressed ? 1 : 0);
            insert.Parameters.AddWithValue("$is_sparse", candidate.IsSparse ? 1 : 0);
            insert.Parameters.AddWithValue("$is_encrypted", candidate.IsEncrypted ? 1 : 0);
            insert.Parameters.AddWithValue("$name", candidate.Name is null ? DBNull.Value : candidate.Name);
            insert.Parameters.AddWithValue("$original_path", candidate.OriginalPath is null ? DBNull.Value : candidate.OriginalPath);
            insert.Parameters.AddWithValue(
                "$parent_record_number",
                candidate.ParentRecordNumber.HasValue ? (object)(long)candidate.ParentRecordNumber.Value : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$data_size_bytes",
                candidate.DataSizeBytes.HasValue ? (object)checked((long)candidate.DataSizeBytes.Value) : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$allocated_size_bytes",
                candidate.AllocatedSizeBytes.HasValue ? (object)checked((long)candidate.AllocatedSizeBytes.Value) : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$file_attributes",
                candidate.FileAttributes.HasValue ? (object)(long)candidate.FileAttributes.Value : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$created_filetime_utc",
                candidate.CreatedFileTimeUtc.HasValue ? (object)checked((long)candidate.CreatedFileTimeUtc.Value) : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$modified_filetime_utc",
                candidate.ModifiedFileTimeUtc.HasValue ? (object)checked((long)candidate.ModifiedFileTimeUtc.Value) : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$mft_modified_filetime_utc",
                candidate.MftModifiedFileTimeUtc.HasValue ? (object)checked((long)candidate.MftModifiedFileTimeUtc.Value) : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$accessed_filetime_utc",
                candidate.AccessedFileTimeUtc.HasValue ? (object)checked((long)candidate.AccessedFileTimeUtc.Value) : DBNull.Value);
            insert.Parameters.AddWithValue("$evidence_sources", candidate.EvidenceSources);
            insert.Parameters.AddWithValue("$confidence_tier", candidate.ConfidenceTier);
            insert.Parameters.AddWithValue("$confidence_reason", candidate.ConfidenceReason);
            insert.Parameters.AddWithValue("$candidate_status", candidate.CandidateStatus.ToStorageCode());
            insert.Parameters.AddWithValue(
                "$recovery_diagnostics",
                candidate.RecoveryDiagnostics is null ? DBNull.Value : candidate.RecoveryDiagnostics);
            insert.Parameters.AddWithValue(
                "$last_recovery_status_code",
                candidate.LastRecoveryStatusCode.HasValue ? (object)candidate.LastRecoveryStatusCode.Value : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$last_recovery_diagnostics_flags",
                candidate.LastRecoveryDiagnosticsFlags.HasValue ? (object)(long)candidate.LastRecoveryDiagnosticsFlags.Value : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$last_recovery_bytes",
                candidate.LastRecoveredBytes.HasValue ? (object)checked((long)candidate.LastRecoveredBytes.Value) : DBNull.Value);
            insert.Parameters.AddWithValue(
                "$last_recovery_partial",
                !candidate.LastRecoveryPartial.HasValue ? DBNull.Value : candidate.LastRecoveryPartial.Value ? 1 : 0);
            insert.Parameters.AddWithValue(
                "$last_recovery_utc",
                candidate.LastRecoveryUtc.HasValue ? (object)candidate.LastRecoveryUtc.Value.ToString("O") : DBNull.Value);

            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<Guid> CreateSessionAsync(
        SourceCandidate source,
        string destinationPath,
        ScanMode scanMode,
        CancellationToken cancellationToken)
    {
        var sessionId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO sessions (
              session_id,
              created_utc,
              updated_utc,
              source_id,
              source_kind,
              destination_path,
              scan_mode,
              status,
              notes
            ) VALUES (
              $session_id,
              $created_utc,
              $updated_utc,
              $source_id,
              $source_kind,
              $destination_path,
              $scan_mode,
              $status,
              $notes
            );
            """;

        command.Parameters.AddWithValue("$session_id", sessionId.ToString("D"));
        command.Parameters.AddWithValue("$created_utc", now.ToString("O"));
        command.Parameters.AddWithValue("$updated_utc", now.ToString("O"));
        command.Parameters.AddWithValue("$source_id", source.Id);
        command.Parameters.AddWithValue("$source_kind", (int)source.Kind);
        command.Parameters.AddWithValue("$destination_path", Path.GetFullPath(destinationPath));
        command.Parameters.AddWithValue("$scan_mode", (int)scanMode);
        command.Parameters.AddWithValue("$status", "initialized");
        command.Parameters.AddWithValue("$notes", DBNull.Value);

        await command.ExecuteNonQueryAsync(cancellationToken);
        return sessionId;
    }

    public async Task UpdateStatusAsync(
        Guid sessionId,
        string status,
        string? notes,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE sessions
            SET updated_utc = $updated_utc,
                status = $status,
                notes = $notes
            WHERE session_id = $session_id;
            """;

        command.Parameters.AddWithValue("$session_id", sessionId.ToString("D"));
        command.Parameters.AddWithValue("$updated_utc", DateTimeOffset.UtcNow.ToString("O"));
        command.Parameters.AddWithValue("$status", status);
        command.Parameters.AddWithValue("$notes", notes is null ? DBNull.Value : notes);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SessionRecord>> GetRecentSessionsAsync(int limit, CancellationToken cancellationToken)
    {
        var records = new List<SessionRecord>();

        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
              session_id,
              created_utc,
              updated_utc,
              source_id,
              source_kind,
              destination_path,
              scan_mode,
              status,
              notes
            FROM sessions
            ORDER BY updated_utc DESC
            LIMIT $limit;
            """;
        command.Parameters.AddWithValue("$limit", limit);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var sessionId = Guid.Parse(reader.GetString(0));
            var createdUtc = DateTimeOffset.Parse(reader.GetString(1));
            var updatedUtc = DateTimeOffset.Parse(reader.GetString(2));
            var sourceId = reader.GetString(3);
            var sourceKind = (RecoverySourceKind)reader.GetInt32(4);
            var destinationPath = reader.GetString(5);
            var scanMode = (ScanMode)reader.GetInt32(6);
            var recordStatus = reader.GetString(7);
            var recordNotes = reader.IsDBNull(8) ? null : reader.GetString(8);

            records.Add(new SessionRecord(
                SessionId: sessionId,
                CreatedUtc: createdUtc,
                UpdatedUtc: updatedUtc,
                SourceId: sourceId,
                SourceKind: sourceKind,
                DestinationPath: destinationPath,
                ScanMode: scanMode,
                Status: recordStatus,
                Notes: recordNotes));
        }

        return records;
    }

    public async Task<IReadOnlyList<QuickScanCandidateRecord>> GetQuickScanCandidatesAsync(
        Guid sessionId,
        int limit,
        CancellationToken cancellationToken)
    {
        var rows = new List<QuickScanCandidateRecord>();

        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
              ordinal,
              record_number,
              deleted,
              is_ghost_record,
              is_directory,
              non_resident_data,
              has_named_data_streams,
              is_compressed,
              is_sparse,
              is_encrypted,
              name,
              original_path,
              parent_record_number,
              data_size_bytes,
              allocated_size_bytes,
              file_attributes,
              created_filetime_utc,
              modified_filetime_utc,
              mft_modified_filetime_utc,
              accessed_filetime_utc,
              evidence_sources,
              confidence_tier,
              confidence_reason,
              candidate_status,
              recovery_diagnostics,
              last_recovery_status_code,
              last_recovery_diagnostics_flags,
              last_recovery_bytes,
              last_recovery_partial,
              last_recovery_utc
            FROM quick_scan_candidates
            WHERE session_id = $session_id
            ORDER BY ordinal ASC
            LIMIT $limit;
            """;

        command.Parameters.AddWithValue("$session_id", sessionId.ToString("D"));
        command.Parameters.AddWithValue("$limit", limit);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var ordinal = reader.GetInt32(0);
            var recordNumber = checked((uint)reader.GetInt64(1));
            var deleted = reader.GetInt32(2) != 0;
            var isGhostRecord = reader.GetInt32(3) != 0;
            var isDirectory = reader.GetInt32(4) != 0;
            var nonResidentData = reader.GetInt32(5) != 0;
            var hasNamedDataStreams = reader.GetInt32(6) != 0;
            var isCompressed = reader.GetInt32(7) != 0;
            var isSparse = reader.GetInt32(8) != 0;
            var isEncrypted = reader.GetInt32(9) != 0;
            var name = reader.IsDBNull(10) ? null : reader.GetString(10);
            var originalPath = reader.IsDBNull(11) ? null : reader.GetString(11);
            ulong? parentRecord = reader.IsDBNull(12) ? null : checked((ulong?)reader.GetInt64(12));
            ulong? dataSizeBytes = reader.IsDBNull(13) ? null : checked((ulong?)reader.GetInt64(13));
            ulong? allocatedSizeBytes = reader.IsDBNull(14) ? null : checked((ulong?)reader.GetInt64(14));
            uint? fileAttributes = reader.IsDBNull(15) ? null : checked((uint?)reader.GetInt64(15));
            ulong? createdFileTimeUtc = reader.IsDBNull(16) ? null : checked((ulong?)reader.GetInt64(16));
            ulong? modifiedFileTimeUtc = reader.IsDBNull(17) ? null : checked((ulong?)reader.GetInt64(17));
            ulong? mftModifiedFileTimeUtc = reader.IsDBNull(18) ? null : checked((ulong?)reader.GetInt64(18));
            ulong? accessedFileTimeUtc = reader.IsDBNull(19) ? null : checked((ulong?)reader.GetInt64(19));
            var evidenceSources = reader.IsDBNull(20) ? "MFT" : reader.GetString(20);
            var confidenceTier = reader.IsDBNull(21) ? "Medium" : reader.GetString(21);
            var confidenceReason = reader.IsDBNull(22) ? string.Empty : reader.GetString(22);
            var candidateStatus = RecoveryCandidateStatusExtensions.FromStorageCode(
                reader.IsDBNull(23) ? null : reader.GetString(23));
            var recoveryDiagnostics = reader.IsDBNull(24) ? null : reader.GetString(24);
            var lastRecoveryStatusCode = reader.IsDBNull(25) ? null : (int?)reader.GetInt32(25);
            uint? lastRecoveryDiagnosticsFlags = reader.IsDBNull(26) ? null : checked((uint?)reader.GetInt64(26));
            ulong? lastRecoveryBytes = reader.IsDBNull(27) ? null : checked((ulong?)reader.GetInt64(27));
            var lastRecoveryPartial = reader.IsDBNull(28) ? null : (bool?)(reader.GetInt32(28) != 0);
            var lastRecoveryUtc = reader.IsDBNull(29) ? null : (DateTimeOffset?)DateTimeOffset.Parse(reader.GetString(29));

            rows.Add(new QuickScanCandidateRecord(
                Ordinal: ordinal,
                RecordNumber: recordNumber,
                Deleted: deleted,
                IsGhostRecord: isGhostRecord,
                Directory: isDirectory,
                NonResidentData: nonResidentData,
                HasNamedDataStreams: hasNamedDataStreams,
                IsCompressed: isCompressed,
                IsSparse: isSparse,
                IsEncrypted: isEncrypted,
                Name: name,
                OriginalPath: originalPath,
                ParentRecordNumber: parentRecord,
                DataSizeBytes: dataSizeBytes,
                AllocatedSizeBytes: allocatedSizeBytes,
                FileAttributes: fileAttributes,
                CreatedFileTimeUtc: createdFileTimeUtc,
                ModifiedFileTimeUtc: modifiedFileTimeUtc,
                MftModifiedFileTimeUtc: mftModifiedFileTimeUtc,
                AccessedFileTimeUtc: accessedFileTimeUtc,
                EvidenceSources: evidenceSources,
                ConfidenceTier: confidenceTier,
                ConfidenceReason: confidenceReason,
                CandidateStatus: candidateStatus,
                RecoveryDiagnostics: recoveryDiagnostics,
                LastRecoveryStatusCode: lastRecoveryStatusCode,
                LastRecoveryDiagnosticsFlags: lastRecoveryDiagnosticsFlags,
                LastRecoveredBytes: lastRecoveryBytes,
                LastRecoveryPartial: lastRecoveryPartial,
                LastRecoveryUtc: lastRecoveryUtc));
        }

        return rows;
    }

    public async Task UpdateQuickScanCandidateRecoveryAsync(
        Guid sessionId,
        int ordinal,
        RecoveryCandidateStatus candidateStatus,
        int? lastRecoveryStatusCode,
        uint? lastRecoveryDiagnosticsFlags,
        ulong? lastRecoveredBytes,
        bool? lastRecoveryPartial,
        string? recoveryDiagnostics,
        DateTimeOffset? lastRecoveryUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);

        var command = connection.CreateCommand();
        command.CommandText =
            """
            UPDATE quick_scan_candidates
            SET candidate_status = $candidate_status,
                recovery_diagnostics = $recovery_diagnostics,
                last_recovery_status_code = $last_recovery_status_code,
                last_recovery_diagnostics_flags = $last_recovery_diagnostics_flags,
                last_recovery_bytes = $last_recovery_bytes,
                last_recovery_partial = $last_recovery_partial,
                last_recovery_utc = $last_recovery_utc
            WHERE session_id = $session_id
              AND ordinal = $ordinal;
            """;

        command.Parameters.AddWithValue("$candidate_status", candidateStatus.ToStorageCode());
        command.Parameters.AddWithValue(
            "$recovery_diagnostics",
            recoveryDiagnostics is null ? DBNull.Value : recoveryDiagnostics);
        command.Parameters.AddWithValue(
            "$last_recovery_status_code",
            lastRecoveryStatusCode.HasValue ? (object)lastRecoveryStatusCode.Value : DBNull.Value);
        command.Parameters.AddWithValue(
            "$last_recovery_diagnostics_flags",
            lastRecoveryDiagnosticsFlags.HasValue ? (object)(long)lastRecoveryDiagnosticsFlags.Value : DBNull.Value);
        command.Parameters.AddWithValue(
            "$last_recovery_bytes",
            lastRecoveredBytes.HasValue ? (object)checked((long)lastRecoveredBytes.Value) : DBNull.Value);
        command.Parameters.AddWithValue(
            "$last_recovery_partial",
            !lastRecoveryPartial.HasValue ? DBNull.Value : lastRecoveryPartial.Value ? 1 : 0);
        command.Parameters.AddWithValue(
            "$last_recovery_utc",
            lastRecoveryUtc.HasValue ? (object)lastRecoveryUtc.Value.ToString("O") : DBNull.Value);
        command.Parameters.AddWithValue("$session_id", sessionId.ToString("D"));
        command.Parameters.AddWithValue("$ordinal", ordinal);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<SessionStoreMaintenanceResult> ApplyRetentionPolicyAsync(
        TimeSpan maxSessionAge,
        int maxSessionCount,
        bool compactDatabase,
        CancellationToken cancellationToken)
    {
        if (maxSessionAge <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxSessionAge), "Session age retention must be positive.");
        }

        if (maxSessionCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxSessionCount), "Session retention count must be positive.");
        }

        var cutoffUtc = DateTimeOffset.UtcNow - maxSessionAge;

        await using var connection = new SqliteConnection($"Data Source={DatabasePath}");
        await connection.OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        var deletedByAge = await DeleteSessionsMatchingQueryAsync(
            connection,
            transaction,
            """
            SELECT session_id
            FROM sessions
            WHERE updated_utc < $cutoff_utc
            """,
            command => command.Parameters.AddWithValue("$cutoff_utc", cutoffUtc.ToString("O")),
            cancellationToken);

        var deletedByOverflow = await DeleteSessionsMatchingQueryAsync(
            connection,
            transaction,
            """
            SELECT session_id
            FROM sessions
            ORDER BY updated_utc DESC
            LIMIT -1 OFFSET $offset
            """,
            command => command.Parameters.AddWithValue("$offset", maxSessionCount),
            cancellationToken);

        await transaction.CommitAsync(cancellationToken);

        var remainingSessions = await GetSessionCountAsync(connection, cancellationToken);
        var compacted = false;
        if (compactDatabase)
        {
            var vacuum = connection.CreateCommand();
            vacuum.CommandText = "VACUUM;";
            await vacuum.ExecuteNonQueryAsync(cancellationToken);
            compacted = true;
        }

        return new SessionStoreMaintenanceResult(
            DeletedByAge: deletedByAge,
            DeletedByOverflow: deletedByOverflow,
            RemainingSessions: remainingSessions,
            Compacted: compacted);
    }

    private static async Task EnsureQuickScanCandidateSchemaAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "confidence_tier",
            "TEXT NOT NULL DEFAULT 'Medium'",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "confidence_reason",
            "TEXT NOT NULL DEFAULT ''",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "candidate_status",
            "TEXT NOT NULL DEFAULT 'partial'",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "is_ghost_record",
            "INTEGER NOT NULL DEFAULT 0",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "has_named_data_streams",
            "INTEGER NOT NULL DEFAULT 0",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "is_compressed",
            "INTEGER NOT NULL DEFAULT 0",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "is_sparse",
            "INTEGER NOT NULL DEFAULT 0",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "is_encrypted",
            "INTEGER NOT NULL DEFAULT 0",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "evidence_sources",
            "TEXT NOT NULL DEFAULT 'MFT'",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "data_size_bytes",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "allocated_size_bytes",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "file_attributes",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "created_filetime_utc",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "modified_filetime_utc",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "mft_modified_filetime_utc",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "accessed_filetime_utc",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "recovery_diagnostics",
            "TEXT NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "last_recovery_status_code",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "last_recovery_diagnostics_flags",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "last_recovery_bytes",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "last_recovery_partial",
            "INTEGER NULL",
            cancellationToken);
        await EnsureQuickScanCandidateColumnAsync(
            connection,
            "last_recovery_utc",
            "TEXT NULL",
            cancellationToken);
    }

    private static async Task EnsureQuickScanCandidateColumnAsync(
        SqliteConnection connection,
        string columnName,
        string columnDefinition,
        CancellationToken cancellationToken)
    {
        if (await HasQuickScanCandidateColumnAsync(connection, columnName, cancellationToken))
        {
            return;
        }

        var alter = connection.CreateCommand();
        alter.CommandText = $"ALTER TABLE quick_scan_candidates ADD COLUMN {columnName} {columnDefinition};";
        await alter.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<bool> HasQuickScanCandidateColumnAsync(
        SqliteConnection connection,
        string columnName,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT 1
            FROM pragma_table_info('quick_scan_candidates')
            WHERE name = $name
            LIMIT 1;
            """;
        command.Parameters.AddWithValue("$name", columnName);

        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is not null;
    }

    private static async Task<int> DeleteSessionsMatchingQueryAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sessionIdSelectionQuery,
        Action<SqliteCommand>? configureSelection,
        CancellationToken cancellationToken)
    {
        var dropTemp = connection.CreateCommand();
        dropTemp.Transaction = transaction;
        dropTemp.CommandText = "DROP TABLE IF EXISTS temp_sessions_to_prune;";
        await dropTemp.ExecuteNonQueryAsync(cancellationToken);

        var createTemp = connection.CreateCommand();
        createTemp.Transaction = transaction;
        createTemp.CommandText = "CREATE TEMP TABLE temp_sessions_to_prune(session_id TEXT PRIMARY KEY);";
        await createTemp.ExecuteNonQueryAsync(cancellationToken);

        var fillTemp = connection.CreateCommand();
        fillTemp.Transaction = transaction;
        fillTemp.CommandText = $"INSERT INTO temp_sessions_to_prune(session_id) {sessionIdSelectionQuery};";
        configureSelection?.Invoke(fillTemp);
        await fillTemp.ExecuteNonQueryAsync(cancellationToken);

        var count = connection.CreateCommand();
        count.Transaction = transaction;
        count.CommandText = "SELECT COUNT(1) FROM temp_sessions_to_prune;";
        var rawCount = await count.ExecuteScalarAsync(cancellationToken);
        var removedCount = rawCount is null ? 0 : Convert.ToInt32(rawCount);

        if (removedCount > 0)
        {
            var deleteCandidates = connection.CreateCommand();
            deleteCandidates.Transaction = transaction;
            deleteCandidates.CommandText =
                """
                DELETE FROM quick_scan_candidates
                WHERE session_id IN (SELECT session_id FROM temp_sessions_to_prune);
                """;
            await deleteCandidates.ExecuteNonQueryAsync(cancellationToken);

            var deleteSessions = connection.CreateCommand();
            deleteSessions.Transaction = transaction;
            deleteSessions.CommandText =
                """
                DELETE FROM sessions
                WHERE session_id IN (SELECT session_id FROM temp_sessions_to_prune);
                """;
            await deleteSessions.ExecuteNonQueryAsync(cancellationToken);
        }

        var cleanupTemp = connection.CreateCommand();
        cleanupTemp.Transaction = transaction;
        cleanupTemp.CommandText = "DROP TABLE IF EXISTS temp_sessions_to_prune;";
        await cleanupTemp.ExecuteNonQueryAsync(cancellationToken);

        return removedCount;
    }

    private static async Task<int> GetSessionCountAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(1) FROM sessions;";
        var raw = await command.ExecuteScalarAsync(cancellationToken);
        return raw is null ? 0 : Convert.ToInt32(raw);
    }
}
