using System.Text.Json;

namespace FileRecovery.WindowsApp.Core.Persistence;

public sealed class SessionLogWriter
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    private readonly string _logDirectory;

    public SessionLogWriter(string? logDirectory = null)
    {
        _logDirectory = string.IsNullOrWhiteSpace(logDirectory)
            ? FileRecoveryPaths.LogDirectory
            : logDirectory;
    }

    public async Task CreateSessionLogsAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_logDirectory);

        var jsonPath = GetJsonLogPath(sessionId);
        var textPath = GetTextLogPath(sessionId);

        if (!File.Exists(jsonPath))
        {
            await File.WriteAllTextAsync(jsonPath, string.Empty, cancellationToken);
        }

        if (!File.Exists(textPath))
        {
            await File.WriteAllTextAsync(textPath, $"Session {sessionId:D}{Environment.NewLine}", cancellationToken);
        }
    }

    public async Task LogEventAsync(Guid sessionId, string eventName, object payload, CancellationToken cancellationToken)
    {
        var record = new
        {
            timestamp_utc = DateTimeOffset.UtcNow,
            event_name = eventName,
            payload,
        };

        var line = JsonSerializer.Serialize(record, SerializerOptions) + Environment.NewLine;
        await File.AppendAllTextAsync(GetJsonLogPath(sessionId), line, cancellationToken);
    }

    public async Task LogMessageAsync(Guid sessionId, string message, CancellationToken cancellationToken)
    {
        var line = $"[{DateTimeOffset.UtcNow:O}] {message}{Environment.NewLine}";
        await File.AppendAllTextAsync(GetTextLogPath(sessionId), line, cancellationToken);
    }

    public async Task<string> WriteRecoveryReportAsync(
        Guid sessionId,
        string reportMarkdown,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_logDirectory);
        var reportPath = GetRecoveryReportPath(sessionId);
        await File.WriteAllTextAsync(reportPath, reportMarkdown, cancellationToken);
        return reportPath;
    }

    private string GetJsonLogPath(Guid sessionId)
    {
        return Path.Combine(_logDirectory, $"{sessionId:D}.jsonl");
    }

    private string GetTextLogPath(Guid sessionId)
    {
        return Path.Combine(_logDirectory, $"{sessionId:D}.log");
    }

    private string GetRecoveryReportPath(Guid sessionId)
    {
        return Path.Combine(_logDirectory, $"{sessionId:D}.recovery-report.md");
    }
}
