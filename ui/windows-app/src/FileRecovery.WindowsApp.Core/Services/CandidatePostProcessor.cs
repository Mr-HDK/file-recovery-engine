using FileRecovery.WindowsApp.Core.Models;
using System.Globalization;
using System.Text.RegularExpressions;

namespace FileRecovery.WindowsApp.Core.Services;

public interface ICarveOcrNameHintProvider
{
    bool TrySuggestName(
        QuickScanCandidateRecord candidate,
        out string suggestedBaseName,
        out string reason);
}

public sealed record ProcessedQuickScanCandidate(
    QuickScanCandidateRecord Candidate,
    string ClusterId,
    int ClusterSize,
    int DeduplicatedCount,
    string ClusterKey);

public sealed record CandidatePostProcessResult(
    IReadOnlyList<ProcessedQuickScanCandidate> Candidates,
    int InputCount,
    int ClusterCount,
    int RemovedDuplicateCount);

public sealed class CandidatePostProcessor
{
    private static readonly Regex MetadataTokenRegex = new(
        "(?i)(title|subject|author|camera|device|model|date|datetime|taken)\\s*[:=]\\s*([^;|,]{3,96})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private readonly ICarveOcrNameHintProvider? _ocrNameHintProvider;

    public CandidatePostProcessor(ICarveOcrNameHintProvider? ocrNameHintProvider = null)
    {
        _ocrNameHintProvider = ocrNameHintProvider;
    }

    public CandidatePostProcessResult Process(IReadOnlyList<QuickScanCandidateRecord> candidates)
    {
        if (candidates.Count == 0)
        {
            return new CandidatePostProcessResult(Array.Empty<ProcessedQuickScanCandidate>(), 0, 0, 0);
        }

        var normalized = candidates
            .Select((candidate, index) => NormalizeCandidate(candidate, index))
            .ToArray();

        var grouped = normalized
            .GroupBy(candidate => BuildClusterKey(candidate.Candidate), StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group.Min(item => item.OriginalOrdinal))
            .ToArray();

        var output = new List<ProcessedQuickScanCandidate>(grouped.Length);
        var removed = 0;
        var clusterOrdinal = 1;

        foreach (var group in grouped)
        {
            var clusterItems = group.ToArray();
            var representative = SelectRepresentative(clusterItems);
            var clusterId = $"C{clusterOrdinal:D4}";
            clusterOrdinal++;
            removed += clusterItems.Length - 1;

            var mergedEvidence = MergeEvidenceSources(clusterItems.Select(item => item.Candidate.EvidenceSources));
            var bestStatus = SelectBestStatus(clusterItems.Select(item => item.Candidate.CandidateStatus));
            var confidenceTier = SelectBestConfidenceTier(clusterItems.Select(item => item.Candidate.ConfidenceTier));
            var confidenceReason = BuildMergedConfidenceReason(representative.Candidate.ConfidenceReason, clusterItems.Length, clusterId);

            var merged = representative.Candidate with
            {
                Ordinal = output.Count,
                EvidenceSources = mergedEvidence,
                CandidateStatus = bestStatus,
                ConfidenceTier = confidenceTier,
                ConfidenceReason = confidenceReason,
                Deleted = clusterItems.Any(item => item.Candidate.Deleted),
                HasNamedDataStreams = clusterItems.Any(item => item.Candidate.HasNamedDataStreams),
                IsCompressed = clusterItems.Any(item => item.Candidate.IsCompressed),
                IsSparse = clusterItems.Any(item => item.Candidate.IsSparse),
                IsEncrypted = clusterItems.Any(item => item.Candidate.IsEncrypted),
                LastRecoveryStatusCode = SelectBestRecoveryCode(clusterItems.Select(item => item.Candidate.LastRecoveryStatusCode)),
                LastRecoveryDiagnosticsFlags = representative.Candidate.LastRecoveryDiagnosticsFlags,
                LastRecoveredBytes = clusterItems
                    .Select(item => item.Candidate.LastRecoveredBytes)
                    .Where(bytes => bytes.HasValue)
                    .Select(bytes => bytes!.Value)
                    .DefaultIfEmpty()
                    .Max(),
            };

            output.Add(new ProcessedQuickScanCandidate(
                merged,
                clusterId,
                clusterItems.Length,
                clusterItems.Length - 1,
                group.Key));
        }

        return new CandidatePostProcessResult(
            output,
            candidates.Count,
            grouped.Length,
            removed);
    }

    private NormalizedCandidate NormalizeCandidate(QuickScanCandidateRecord candidate, int originalOrdinal)
    {
        var normalizedEvidence = NormalizeEvidenceSources(candidate.EvidenceSources);
        var normalizedFormat = NormalizeCarveFormat(candidate.CarveFormat, candidate.Name, candidate.OriginalPath);
        var metadataHint = TryExtractMetadataHint(candidate);
        var normalizedName = BuildNormalizedName(candidate, normalizedFormat, metadataHint);
        var normalizedPath = BuildNormalizedPath(candidate.OriginalPath, candidate.Name, normalizedName);

        var normalized = candidate with
        {
            Ordinal = originalOrdinal,
            Name = normalizedName,
            OriginalPath = normalizedPath,
            EvidenceSources = normalizedEvidence,
            CarveFormat = normalizedFormat,
        };

        return new NormalizedCandidate(normalized, originalOrdinal);
    }

    private static string BuildClusterKey(QuickScanCandidateRecord candidate)
    {
        var normalizedPath = NormalizePathForCluster(candidate.OriginalPath);
        var hasStrongPath = !string.IsNullOrWhiteSpace(normalizedPath)
            && !normalizedPath.StartsWith("recovered\\", StringComparison.OrdinalIgnoreCase);

        if (hasStrongPath)
        {
            var pathSize = candidate.DataSizeBytes ?? candidate.CarveLengthBytes ?? 0;
            return $"path:{normalizedPath}|size:{pathSize.ToString(CultureInfo.InvariantCulture)}";
        }

        var normalizedName = NormalizeNameForCluster(candidate.Name);
        var extension = NormalizeExtension(candidate.Name, candidate.CarveFormat);
        var size = candidate.DataSizeBytes ?? candidate.CarveLengthBytes ?? 0;
        var modifiedBucket = BucketFileTime(candidate.ModifiedFileTimeUtc ?? candidate.CreatedFileTimeUtc);
        return $"name:{normalizedName}|ext:{extension}|size:{size.ToString(CultureInfo.InvariantCulture)}|modified:{modifiedBucket.ToString(CultureInfo.InvariantCulture)}";
    }

    private static ulong BucketFileTime(ulong? fileTimeUtc)
    {
        if (!fileTimeUtc.HasValue || fileTimeUtc.Value == 0)
        {
            return 0;
        }

        return fileTimeUtc.Value / 10_000_000UL;
    }

    private static NormalizedCandidate SelectRepresentative(IReadOnlyList<NormalizedCandidate> candidates)
    {
        return candidates
            .OrderByDescending(candidate => ComputeCandidateScore(candidate.Candidate))
            .ThenBy(candidate => candidate.OriginalOrdinal)
            .First();
    }

    private static long ComputeCandidateScore(QuickScanCandidateRecord candidate)
    {
        var score = 0L;
        score += RankStatus(candidate.CandidateStatus) * 1_000_000L;
        score += RankConfidenceTier(candidate.ConfidenceTier) * 100_000L;
        score += CountEvidenceSources(candidate.EvidenceSources) * 10_000L;

        if (candidate.Deleted)
        {
            score += 2_000L;
        }
        if (!candidate.IsGhostRecord)
        {
            score += 2_000L;
        }
        if (!candidate.Directory)
        {
            score += 2_000L;
        }
        if (!LooksUnknownName(candidate.Name))
        {
            score += 1_500L;
        }
        if (!LooksUnknownPath(candidate.OriginalPath))
        {
            score += 1_500L;
        }
        if (candidate.DataSizeBytes.HasValue)
        {
            score += 1_000L;
        }
        if (!IsCarveEvidence(candidate.EvidenceSources))
        {
            score += 500L;
        }

        return score;
    }

    private static int RankStatus(RecoveryCandidateStatus status)
    {
        return status switch
        {
            RecoveryCandidateStatus.Full => 4,
            RecoveryCandidateStatus.Partial => 3,
            RecoveryCandidateStatus.OverwrittenRisk => 2,
            _ => 1,
        };
    }

    private static RecoveryCandidateStatus SelectBestStatus(IEnumerable<RecoveryCandidateStatus> statuses)
    {
        return statuses
            .OrderByDescending(RankStatus)
            .FirstOrDefault();
    }

    private static int RankConfidenceTier(string? tier)
    {
        return tier?.Trim().ToLowerInvariant() switch
        {
            "very high" => 5,
            "high" => 4,
            "medium" => 3,
            "low" => 2,
            "very low" => 1,
            _ => 0,
        };
    }

    private static string SelectBestConfidenceTier(IEnumerable<string> tiers)
    {
        return tiers
            .OrderByDescending(RankConfidenceTier)
            .FirstOrDefault() ?? "Medium";
    }

    private static int? SelectBestRecoveryCode(IEnumerable<int?> codes)
    {
        var materialized = codes.Where(code => code.HasValue).Select(code => code!.Value).ToArray();
        if (materialized.Length == 0)
        {
            return null;
        }

        if (materialized.Contains(0))
        {
            return 0;
        }

        return materialized.Min();
    }

    private static int CountEvidenceSources(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return 0;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();
    }

    private static string MergeEvidenceSources(IEnumerable<string> evidenceSources)
    {
        var ordered = evidenceSources
            .SelectMany(value => (value ?? string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => EvidencePriority(value))
            .ThenBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (ordered.Length == 0)
        {
            return "MFT";
        }

        return string.Join(", ", ordered);
    }

    private static int EvidencePriority(string source)
    {
        return source.ToUpperInvariant() switch
        {
            "MFT" => 0,
            "DIRECTORY_INDEX" => 1,
            "USN" => 2,
            "VSS" => 3,
            "CARVE" => 4,
            _ => 5,
        };
    }

    private static string BuildMergedConfidenceReason(string? originalReason, int clusterSize, string clusterId)
    {
        var reason = string.IsNullOrWhiteSpace(originalReason)
            ? "Confidence reason unavailable."
            : originalReason.Trim();

        if (clusterSize <= 1)
        {
            return reason;
        }

        return $"{reason} Cluster {clusterId} merged {clusterSize} near-identical candidates.";
    }

    private static string NormalizeEvidenceSources(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return "MFT";
        }

        return MergeEvidenceSources(new[] { evidenceSources });
    }

    private static string NormalizeCarveFormat(string? carveFormat, string? name, string? originalPath)
    {
        if (!string.IsNullOrWhiteSpace(carveFormat))
        {
            return carveFormat.Trim().TrimStart('.').ToLowerInvariant();
        }

        var ext = Path.GetExtension(name);
        if (string.IsNullOrWhiteSpace(ext))
        {
            ext = Path.GetExtension(originalPath);
        }

        if (string.IsNullOrWhiteSpace(ext))
        {
            return string.Empty;
        }

        return ext.Trim().TrimStart('.').ToLowerInvariant();
    }

    private string? TryExtractMetadataHint(QuickScanCandidateRecord candidate)
    {
        if (!IsCarveEvidence(candidate.EvidenceSources))
        {
            return null;
        }

        var reason = candidate.ConfidenceReason ?? string.Empty;
        var match = MetadataTokenRegex.Match(reason);
        if (match.Success)
        {
            return SanitizeBaseName(match.Groups[2].Value);
        }

        if (_ocrNameHintProvider is not null
            && _ocrNameHintProvider.TrySuggestName(candidate, out var ocrName, out _))
        {
            return SanitizeBaseName(ocrName);
        }

        return null;
    }

    private static string BuildNormalizedName(
        QuickScanCandidateRecord candidate,
        string normalizedFormat,
        string? metadataHint)
    {
        if (!LooksUnknownName(candidate.Name))
        {
            return SanitizeFileName(candidate.Name!);
        }

        var ext = NormalizeExtension(candidate.Name, normalizedFormat);
        if (candidate.Directory)
        {
            return $"folder-record-{candidate.RecordNumber.ToString(CultureInfo.InvariantCulture)}";
        }

        if (IsCarveEvidence(candidate.EvidenceSources))
        {
            if (!string.IsNullOrWhiteSpace(metadataHint))
            {
                return $"carve-{metadataHint}{ext}";
            }

            var timestamp = BuildTimestampSuffix(candidate.ModifiedFileTimeUtc ?? candidate.CreatedFileTimeUtc);
            if (!string.IsNullOrWhiteSpace(timestamp))
            {
                return $"carve-{timestamp}-{candidate.RecordNumber.ToString(CultureInfo.InvariantCulture)}{ext}";
            }

            if (candidate.CarveOffsetBytes.HasValue)
            {
                return $"carve-offset-{candidate.CarveOffsetBytes.Value.ToString("X", CultureInfo.InvariantCulture)}{ext}";
            }

            return $"carve-record-{candidate.RecordNumber.ToString(CultureInfo.InvariantCulture)}{ext}";
        }

        return $"file-record-{candidate.RecordNumber.ToString(CultureInfo.InvariantCulture)}{ext}";
    }

    private static string BuildTimestampSuffix(ulong? fileTimeUtc)
    {
        if (!fileTimeUtc.HasValue || fileTimeUtc.Value == 0 || fileTimeUtc.Value > long.MaxValue)
        {
            return string.Empty;
        }

        try
        {
            var utc = DateTimeOffset.FromFileTime((long)fileTimeUtc.Value).UtcDateTime;
            return utc.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string BuildNormalizedPath(string? originalPath, string? originalName, string normalizedName)
    {
        if (!LooksUnknownPath(originalPath))
        {
            var parts = originalPath!
                .Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(SanitizePathSegment)
                .Where(part => !string.IsNullOrWhiteSpace(part))
                .ToArray();
            if (parts.Length > 0)
            {
                var leaf = parts[^1];
                if (LooksUnknownName(originalName)
                    || string.Equals(leaf, SanitizePathSegment(originalName ?? string.Empty), StringComparison.OrdinalIgnoreCase))
                {
                    parts[^1] = normalizedName;
                }

                return Path.Combine(parts);
            }
        }

        return Path.Combine("Recovered", normalizedName);
    }

    private static string NormalizePathForCluster(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        var parts = path
            .Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Trim())
            .Where(part => !string.IsNullOrWhiteSpace(part))
            .Select(part => part.Equals(".", StringComparison.Ordinal) ? string.Empty : part)
            .Where(part => !string.IsNullOrWhiteSpace(part))
            .ToArray();
        if (parts.Length == 0)
        {
            return string.Empty;
        }

        return string.Join("\\", parts).ToLowerInvariant();
    }

    private static string NormalizeNameForCluster(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "(unknown)";
        }

        var cleaned = Path.GetFileNameWithoutExtension(name.Trim()).ToLowerInvariant();
        return string.IsNullOrWhiteSpace(cleaned) ? "(unknown)" : cleaned;
    }

    private static string NormalizeExtension(string? name, string? format)
    {
        var ext = Path.GetExtension(name);
        if (string.IsNullOrWhiteSpace(ext))
        {
            ext = format;
        }

        if (string.IsNullOrWhiteSpace(ext))
        {
            return ".bin";
        }

        ext = ext.Trim();
        if (!ext.StartsWith(".", StringComparison.Ordinal))
        {
            ext = "." + ext;
        }

        return SanitizeExtension(ext.ToLowerInvariant());
    }

    private static string SanitizeExtension(string extension)
    {
        var filtered = new string(extension.Where(ch => ch == '.' || char.IsLetterOrDigit(ch)).ToArray());
        if (string.IsNullOrWhiteSpace(filtered) || filtered == ".")
        {
            return ".bin";
        }

        return filtered;
    }

    private static bool LooksUnknownName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return true;
        }

        var normalized = name.Trim();
        if (normalized is "(unknown)" or "-" or "_")
        {
            return true;
        }

        return normalized.StartsWith("record-", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("carve_", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("carve-", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("unnamed", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksUnknownPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return true;
        }

        var normalized = path.Trim();
        return normalized is "(unresolved)" or "(unknown)" or "." or "\\";
    }

    private static bool IsCarveEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(value => string.Equals(value, "Carve", StringComparison.OrdinalIgnoreCase));
    }

    private static string SanitizeBaseName(string value)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var chars = value
            .Trim()
            .ToLowerInvariant()
            .Select(ch => invalidChars.Contains(ch) ? '-' : ch)
            .Select(ch => char.IsLetterOrDigit(ch) ? ch : '-')
            .ToArray();
        var collapsed = new string(chars);
        while (collapsed.Contains("--", StringComparison.Ordinal))
        {
            collapsed = collapsed.Replace("--", "-", StringComparison.Ordinal);
        }

        collapsed = collapsed.Trim('-');
        if (string.IsNullOrWhiteSpace(collapsed))
        {
            return "candidate";
        }

        if (collapsed.Length > 56)
        {
            collapsed = collapsed[..56];
        }

        return collapsed;
    }

    private static string SanitizeFileName(string name)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var chars = name.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray();
        var sanitized = new string(chars).Trim();
        if (string.IsNullOrWhiteSpace(sanitized))
        {
            return "file.bin";
        }

        return sanitized;
    }

    private static string SanitizePathSegment(string segment)
    {
        if (segment is "." or "..")
        {
            return "_";
        }

        var invalidChars = Path.GetInvalidFileNameChars();
        var chars = segment.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray();
        var sanitized = new string(chars).Trim();
        return string.IsNullOrWhiteSpace(sanitized) ? "_" : sanitized;
    }

    private sealed record NormalizedCandidate(
        QuickScanCandidateRecord Candidate,
        int OriginalOrdinal);
}
