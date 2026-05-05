using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed record CandidateTreeEntry(
    string CandidateKey,
    string Name,
    string? OriginalPath,
    bool IsDirectory);

public sealed record CandidateTreeNode(
    string DisplayName,
    string FullPathKey,
    bool IsFolder,
    IReadOnlyList<CandidateTreeNode> Children,
    IReadOnlyList<string> CandidateKeys);

public static class CandidateTreeBuilder
{
    public const string UnresolvedRootName = "Unresolved";

    public static IReadOnlyList<CandidateTreeNode> Build(IEnumerable<CandidateTreeEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var roots = new Dictionary<string, MutableTreeNode>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.CandidateKey))
            {
                continue;
            }

            var segments = BuildPathSegments(entry);
            if (segments.Count == 0)
            {
                continue;
            }

            var currentPath = string.Empty;
            MutableTreeNode? cursor = null;
            for (var index = 0; index < segments.Count; index++)
            {
                var segment = segments[index];
                currentPath = string.IsNullOrWhiteSpace(currentPath)
                    ? segment
                    : currentPath + "\\" + segment;
                var isLeaf = index == segments.Count - 1;
                var isFolder = !isLeaf || entry.IsDirectory;

                if (cursor is null)
                {
                    if (!roots.TryGetValue(segment, out var rootNode))
                    {
                        rootNode = new MutableTreeNode(segment, currentPath, isFolder);
                        roots[segment] = rootNode;
                    }
                    else if (isFolder)
                    {
                        rootNode.IsFolder = true;
                    }

                    cursor = rootNode;
                    continue;
                }

                cursor = cursor.GetOrCreateChild(segment, currentPath, isFolder);
            }

            if (cursor is null)
            {
                continue;
            }

            if (entry.IsDirectory)
            {
                cursor.IsFolder = true;
            }
            else
            {
                cursor.IsFolder = false;
                cursor.CandidateKeys.Add(entry.CandidateKey);
            }
        }

        return roots.Values
            .OrderBy(node => node.IsFolder ? 0 : 1)
            .ThenBy(node => node.DisplayName, StringComparer.OrdinalIgnoreCase)
            .Select(ConvertNode)
            .ToArray();
    }

    public static IReadOnlyList<string> CollectCandidateKeys(
        CandidateTreeNode node,
        bool includeDescendants = true)
    {
        ArgumentNullException.ThrowIfNull(node);

        return EnumerateNodes(node, includeDescendants)
            .SelectMany(current => current.CandidateKeys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(key => key, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> CollectRecoverableCandidateKeys(
        CandidateTreeNode node,
        ISet<string> recoverableCandidateKeys,
        bool includeDescendants = true)
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(recoverableCandidateKeys);

        return CollectCandidateKeys(node, includeDescendants)
            .Where(recoverableCandidateKeys.Contains)
            .ToArray();
    }

    public static string? NormalizePath(string? rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath))
        {
            return null;
        }

        var normalized = rawPath.Trim();
        if (string.Equals(normalized, "(unresolved)", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        normalized = normalized.Replace('/', '\\');
        while (normalized.StartsWith(@".\", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }

        var segments = normalized
            .Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(SanitizePathSegment)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();

        if (segments.Length == 0)
        {
            return null;
        }

        return string.Join("\\", segments);
    }

    private static List<string> BuildPathSegments(CandidateTreeEntry entry)
    {
        var normalizedPath = NormalizePath(entry.OriginalPath);
        if (!string.IsNullOrWhiteSpace(normalizedPath))
        {
            return normalizedPath
                .Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(SanitizePathSegment)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .ToList();
        }

        var fallbackName = string.IsNullOrWhiteSpace(entry.Name)
            ? $"candidate-{entry.CandidateKey.ToLowerInvariant()}"
            : entry.Name;
        return
        [
            UnresolvedRootName,
            SanitizePathSegment(fallbackName),
        ];
    }

    private static string SanitizePathSegment(string segment)
    {
        var value = segment.Trim();
        if (value is "." or "..")
        {
            return "_";
        }

        var invalidChars = Path.GetInvalidFileNameChars();
        var chars = value.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray();
        var sanitized = new string(chars).Trim();
        if (string.IsNullOrWhiteSpace(sanitized))
        {
            return "_";
        }

        return sanitized;
    }

    private static CandidateTreeNode ConvertNode(MutableTreeNode node)
    {
        var children = node.Children.Values
            .OrderBy(child => child.IsFolder ? 0 : 1)
            .ThenBy(child => child.DisplayName, StringComparer.OrdinalIgnoreCase)
            .Select(ConvertNode)
            .ToArray();

        return new CandidateTreeNode(
            DisplayName: node.DisplayName,
            FullPathKey: node.FullPathKey,
            IsFolder: node.IsFolder,
            Children: children,
            CandidateKeys: node.CandidateKeys
                .OrderBy(key => key, StringComparer.OrdinalIgnoreCase)
                .ToArray());
    }

    private static IEnumerable<CandidateTreeNode> EnumerateNodes(
        CandidateTreeNode node,
        bool includeDescendants)
    {
        yield return node;

        if (!includeDescendants)
        {
            yield break;
        }

        foreach (var child in node.Children)
        {
            foreach (var descendant in EnumerateNodes(child, includeDescendants: true))
            {
                yield return descendant;
            }
        }
    }

    private sealed class MutableTreeNode
    {
        public MutableTreeNode(string displayName, string fullPathKey, bool isFolder)
        {
            DisplayName = displayName;
            FullPathKey = fullPathKey;
            IsFolder = isFolder;
        }

        public string DisplayName { get; }
        public string FullPathKey { get; }
        public bool IsFolder { get; set; }
        public Dictionary<string, MutableTreeNode> Children { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> CandidateKeys { get; } = new(StringComparer.OrdinalIgnoreCase);

        public MutableTreeNode GetOrCreateChild(string segment, string fullPathKey, bool isFolder)
        {
            if (!Children.TryGetValue(segment, out var child))
            {
                child = new MutableTreeNode(segment, fullPathKey, isFolder);
                Children[segment] = child;
            }
            else if (isFolder)
            {
                child.IsFolder = true;
            }

            return child;
        }
    }
}
