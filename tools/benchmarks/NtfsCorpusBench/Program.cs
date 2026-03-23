using FileRecovery.WindowsApp.Core.Engine;
using FileRecovery.WindowsApp.Core.Models;
using System.Diagnostics;
using System.Text.Json;

namespace NtfsCorpusBench;

internal static class Program
{
    public static int Main(string[] args)
    {
        var options = BenchmarkOptions.Parse(args);
        if (options is null)
        {
            return 1;
        }

        var manifestPath = Path.GetFullPath(options.ManifestPath);
        if (!File.Exists(manifestPath))
        {
            Console.Error.WriteLine($"Manifest not found: {manifestPath}");
            return 1;
        }

        var manifest = LoadManifest(manifestPath);
        if (manifest.Cases.Count == 0)
        {
            Console.Error.WriteLine("Manifest contains no benchmark cases.");
            return 1;
        }

        var outputPath = ResolveOutputPath(options, manifestPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        var engineVersion = NativeEngineProbe.GetVersionDisplay();
        var engineHealthy = NativeEngineProbe.IsHealthy();

        Console.WriteLine($"Engine version: {engineVersion}");
        Console.WriteLine($"Engine healthy: {engineHealthy}");
        Console.WriteLine($"Manifest: {manifestPath}");
        Console.WriteLine($"Cases: {manifest.Cases.Count}");

        var caseResults = new List<BenchmarkCaseResult>(manifest.Cases.Count);
        var missingCount = 0;
        var failedCount = 0;
        var engineUnavailableCount = 0;

        var manifestDirectory = Path.GetDirectoryName(manifestPath)!;
        foreach (var caseDefinition in manifest.Cases)
        {
            var caseResult = RunCase(caseDefinition, options, manifestDirectory);
            caseResults.Add(caseResult);

            switch (caseResult.Status)
            {
                case "missing":
                    missingCount++;
                    break;
                case "engine-unavailable":
                    engineUnavailableCount++;
                    break;
                case "open-failed":
                case "failed":
                    failedCount++;
                    break;
            }
        }

        var report = new BenchmarkReport
        {
            GeneratedUtc = DateTimeOffset.UtcNow,
            Host = Environment.MachineName,
            Os = Environment.OSVersion.ToString(),
            EngineVersion = engineVersion,
            EngineHealthy = engineHealthy,
            ManifestPath = manifestPath,
            WarmupEnabled = options.Warmup,
            AllowMissing = options.AllowMissing,
            Cases = caseResults,
            Totals = new BenchmarkTotals
            {
                CaseCount = caseResults.Count,
                Ok = caseResults.Count(c => c.Status == "ok"),
                Partial = caseResults.Count(c => c.Status == "partial"),
                Missing = missingCount,
                Failed = failedCount,
                EngineUnavailable = engineUnavailableCount,
            },
        };

        var serializerOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
        };

        var json = JsonSerializer.Serialize(report, serializerOptions);
        File.WriteAllText(outputPath, json);

        Console.WriteLine($"Benchmark report written: {outputPath}");
        Console.WriteLine(
            $"Summary: ok={report.Totals.Ok}, partial={report.Totals.Partial}, missing={report.Totals.Missing}, failed={report.Totals.Failed}, engine-unavailable={report.Totals.EngineUnavailable}");

        if (missingCount > 0 && !options.AllowMissing)
        {
            Console.Error.WriteLine("Benchmark corpus is incomplete. Use --allow-missing for plumbing-only runs.");
            return 2;
        }

        if (failedCount > 0)
        {
            return 3;
        }

        if (engineUnavailableCount > 0)
        {
            return 4;
        }

        return 0;
    }

    private static BenchmarkCaseResult RunCase(
        CorpusCase caseDefinition,
        BenchmarkOptions options,
        string manifestDirectory)
    {
        var relativePath = caseDefinition.RelativePath?.Trim();
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            return new BenchmarkCaseResult
            {
                Id = caseDefinition.Id,
                SourcePath = string.Empty,
                Status = "failed",
                Message = "Case has empty relativePath.",
            };
        }

        var sourcePath = Path.GetFullPath(Path.Combine(manifestDirectory, relativePath));
        if (!File.Exists(sourcePath))
        {
            return new BenchmarkCaseResult
            {
                Id = caseDefinition.Id,
                SourcePath = sourcePath,
                Status = "missing",
                Message = "Image file is missing from fixed corpus.",
            };
        }

        var iterations = options.IterationsOverride ?? caseDefinition.Iterations;
        if (iterations <= 0)
        {
            iterations = 1;
        }

        var maxRecords = options.MaxRecordsOverride ?? caseDefinition.MaxRecords;
        var candidateCapacity = caseDefinition.CandidateCapacity <= 0 ? 1024 : caseDefinition.CandidateCapacity;
        var samples = new List<BenchmarkSample>(iterations);

        var open = NativeEngineProbe.OpenSourceReadOnlySession(sourcePath, RecoverySourceKind.ImageFile);
        if (!open.EngineAvailable)
        {
            return new BenchmarkCaseResult
            {
                Id = caseDefinition.Id,
                SourcePath = sourcePath,
                Status = "engine-unavailable",
                Message = open.Message,
            };
        }

        if (!open.Opened)
        {
            return new BenchmarkCaseResult
            {
                Id = caseDefinition.Id,
                SourcePath = sourcePath,
                Status = "open-failed",
                Message = open.Message,
            };
        }

        try
        {
            if (options.Warmup)
            {
                _ = NativeEngineProbe.QuickScanNtfsFromSession(open.SessionId, maxRecords);
                _ = NativeEngineProbe.GetNtfsQuickScanCandidatesFromSession(open.SessionId, maxRecords, candidateCapacity);
            }

            for (var i = 0; i < iterations; i++)
            {
                var stopwatch = Stopwatch.StartNew();
                var quick = NativeEngineProbe.QuickScanNtfsFromSession(open.SessionId, maxRecords);
                EngineNtfsQuickScanCandidatesResult? candidates = null;
                if (quick.Success)
                {
                    candidates = NativeEngineProbe.GetNtfsQuickScanCandidatesFromSession(
                        open.SessionId,
                        maxRecords,
                        candidateCapacity);
                }

                stopwatch.Stop();

                samples.Add(new BenchmarkSample
                {
                    Iteration = i + 1,
                    ElapsedMs = stopwatch.Elapsed.TotalMilliseconds,
                    QuickScanSuccess = quick.Success,
                    QuickScanStatusCode = quick.StatusCode,
                    ParsedRecords = quick.ParsedRecords,
                    ParseFailures = quick.ParseFailures,
                    DeletedRecords = quick.DeletedRecords,
                    CandidateFetchSuccess = candidates?.Success ?? false,
                    CandidateFetchStatusCode = candidates?.StatusCode ?? -1,
                    CandidateCount = candidates?.Candidates.Count ?? 0,
                });
            }
        }
        finally
        {
            _ = NativeEngineProbe.CloseSourceSession(open.SessionId);
        }

        var meanMs = samples.Average(sample => sample.ElapsedMs);
        var bestMs = samples.Min(sample => sample.ElapsedMs);
        var worstMs = samples.Max(sample => sample.ElapsedMs);
        var avgParsed = samples.Average(sample => sample.ParsedRecords);
        var avgCandidates = samples.Average(sample => sample.CandidateCount);

        var allSuccessful = samples.All(sample => sample.QuickScanSuccess && sample.CandidateFetchSuccess);
        var anySuccessful = samples.Any(sample => sample.QuickScanSuccess || sample.CandidateFetchSuccess);
        var status = allSuccessful ? "ok" : anySuccessful ? "partial" : "failed";
        var message = allSuccessful
            ? "All iterations completed successfully."
            : "One or more iterations returned quick-scan or candidate-fetch failures.";

        return new BenchmarkCaseResult
        {
            Id = caseDefinition.Id,
            SourcePath = sourcePath,
            Status = status,
            Message = message,
            Iterations = iterations,
            MaxRecords = maxRecords,
            MeanElapsedMs = meanMs,
            BestElapsedMs = bestMs,
            WorstElapsedMs = worstMs,
            AverageParsedRecords = avgParsed,
            AverageCandidates = avgCandidates,
            Samples = samples,
        };
    }

    private static CorpusManifest LoadManifest(string manifestPath)
    {
        var json = File.ReadAllText(manifestPath);
        var manifest = JsonSerializer.Deserialize<CorpusManifest>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = true,
        });

        if (manifest is null)
        {
            throw new InvalidOperationException("Failed to parse corpus manifest.");
        }

        return manifest;
    }

    private static string ResolveOutputPath(BenchmarkOptions options, string manifestPath)
    {
        if (!string.IsNullOrWhiteSpace(options.OutputPath))
        {
            return Path.GetFullPath(options.OutputPath);
        }

        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
        var repoRoot = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(manifestPath)!, "..", "..", ".."));
        return Path.Combine(repoRoot, "tools", "benchmark-results", $"ntfs-corpus-{stamp}.json");
    }
}

internal sealed class BenchmarkOptions
{
    public required string ManifestPath { get; init; }
    public string? OutputPath { get; init; }
    public bool AllowMissing { get; init; }
    public bool Warmup { get; init; } = true;
    public int? IterationsOverride { get; init; }
    public uint? MaxRecordsOverride { get; init; }

    public static BenchmarkOptions? Parse(string[] args)
    {
        string? manifestPath = null;
        string? outputPath = null;
        var allowMissing = false;
        var warmup = true;
        int? iterations = null;
        uint? maxRecords = null;

        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--manifest":
                    manifestPath = ReadNext(args, ref i, "--manifest");
                    break;
                case "--output":
                    outputPath = ReadNext(args, ref i, "--output");
                    break;
                case "--allow-missing":
                    allowMissing = true;
                    break;
                case "--iterations":
                    if (!int.TryParse(ReadNext(args, ref i, "--iterations"), out var parsedIterations) || parsedIterations <= 0)
                    {
                        throw new ArgumentException("--iterations must be a positive integer.");
                    }

                    iterations = parsedIterations;
                    break;
                case "--max-records":
                    if (!uint.TryParse(ReadNext(args, ref i, "--max-records"), out var parsedMaxRecords) || parsedMaxRecords == 0)
                    {
                        throw new ArgumentException("--max-records must be a positive integer.");
                    }

                    maxRecords = parsedMaxRecords;
                    break;
                case "--no-warmup":
                    warmup = false;
                    break;
                case "--help":
                case "-h":
                    PrintUsage();
                    return null;
                default:
                    throw new ArgumentException($"Unknown argument: {args[i]}");
            }
        }

        if (string.IsNullOrWhiteSpace(manifestPath))
        {
            PrintUsage();
            throw new ArgumentException("--manifest is required.");
        }

        return new BenchmarkOptions
        {
            ManifestPath = manifestPath,
            OutputPath = outputPath,
            AllowMissing = allowMissing,
            Warmup = warmup,
            IterationsOverride = iterations,
            MaxRecordsOverride = maxRecords,
        };
    }

    private static string ReadNext(string[] args, ref int index, string option)
    {
        if (index + 1 >= args.Length)
        {
            throw new ArgumentException($"Missing value for {option}.");
        }

        index++;
        return args[index];
    }

    private static void PrintUsage()
    {
        Console.WriteLine(
            "Usage: NtfsCorpusBench --manifest <path> [--output <path>] [--allow-missing] [--iterations <n>] [--max-records <n>] [--no-warmup]");
    }
}

internal sealed class CorpusManifest
{
    public string SchemaVersion { get; init; } = "1.0";
    public string Description { get; init; } = string.Empty;
    public List<CorpusCase> Cases { get; init; } = [];
}

internal sealed class CorpusCase
{
    public string Id { get; init; } = string.Empty;
    public string RelativePath { get; init; } = string.Empty;
    public uint MaxRecords { get; init; } = 131072;
    public int Iterations { get; init; } = 3;
    public int CandidateCapacity { get; init; } = 1024;
}

internal sealed class BenchmarkReport
{
    public DateTimeOffset GeneratedUtc { get; init; }
    public string Host { get; init; } = string.Empty;
    public string Os { get; init; } = string.Empty;
    public string EngineVersion { get; init; } = string.Empty;
    public bool EngineHealthy { get; init; }
    public string ManifestPath { get; init; } = string.Empty;
    public bool WarmupEnabled { get; init; }
    public bool AllowMissing { get; init; }
    public List<BenchmarkCaseResult> Cases { get; init; } = [];
    public BenchmarkTotals Totals { get; init; } = new();
}

internal sealed class BenchmarkTotals
{
    public int CaseCount { get; init; }
    public int Ok { get; init; }
    public int Partial { get; init; }
    public int Missing { get; init; }
    public int Failed { get; init; }
    public int EngineUnavailable { get; init; }
}

internal sealed class BenchmarkCaseResult
{
    public string Id { get; init; } = string.Empty;
    public string SourcePath { get; init; } = string.Empty;
    public string Status { get; init; } = "failed";
    public string Message { get; init; } = string.Empty;
    public int Iterations { get; init; }
    public uint MaxRecords { get; init; }
    public double MeanElapsedMs { get; init; }
    public double BestElapsedMs { get; init; }
    public double WorstElapsedMs { get; init; }
    public double AverageParsedRecords { get; init; }
    public double AverageCandidates { get; init; }
    public List<BenchmarkSample> Samples { get; init; } = [];
}

internal sealed class BenchmarkSample
{
    public int Iteration { get; init; }
    public double ElapsedMs { get; init; }
    public bool QuickScanSuccess { get; init; }
    public int QuickScanStatusCode { get; init; }
    public uint ParsedRecords { get; init; }
    public uint ParseFailures { get; init; }
    public uint DeletedRecords { get; init; }
    public bool CandidateFetchSuccess { get; init; }
    public int CandidateFetchStatusCode { get; init; }
    public int CandidateCount { get; init; }
}
