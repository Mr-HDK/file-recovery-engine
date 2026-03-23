using FileRecovery.WindowsApp.Core.Persistence;

namespace FileRecovery.WindowsApp.Tests;

public sealed class SessionLogWriterTests
{
    [Fact]
    public async Task CreateSessionLogsAndReportWritesExpectedArtifacts()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), "fr-tests-logs", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        var writer = new SessionLogWriter(tempRoot);
        var sessionId = Guid.NewGuid();

        await writer.CreateSessionLogsAsync(sessionId, CancellationToken.None);
        await writer.LogEventAsync(sessionId, "candidate_recovery", new { recovered = 2 }, CancellationToken.None);
        await writer.LogMessageAsync(sessionId, "Recovery completed", CancellationToken.None);

        var reportBody = "# Recovery Session Report\n\n- test: true\n";
        var reportPath = await writer.WriteRecoveryReportAsync(sessionId, reportBody, CancellationToken.None);

        var jsonLogPath = Path.Combine(tempRoot, $"{sessionId:D}.jsonl");
        var textLogPath = Path.Combine(tempRoot, $"{sessionId:D}.log");
        var expectedReportPath = Path.Combine(tempRoot, $"{sessionId:D}.recovery-report.md");

        Assert.True(File.Exists(jsonLogPath));
        Assert.True(File.Exists(textLogPath));
        Assert.True(File.Exists(reportPath));
        Assert.Equal(expectedReportPath, reportPath);

        var jsonLog = await File.ReadAllTextAsync(jsonLogPath, CancellationToken.None);
        var textLog = await File.ReadAllTextAsync(textLogPath, CancellationToken.None);
        var report = await File.ReadAllTextAsync(reportPath, CancellationToken.None);

        Assert.Contains("candidate_recovery", jsonLog);
        Assert.Contains("Recovery completed", textLog);
        Assert.Equal(reportBody, report);
    }
}
