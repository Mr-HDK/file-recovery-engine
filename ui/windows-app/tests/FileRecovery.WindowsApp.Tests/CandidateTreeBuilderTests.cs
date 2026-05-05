using FileRecovery.WindowsApp.Core.Services;

namespace FileRecovery.WindowsApp.Tests;

public sealed class CandidateTreeBuilderTests
{
    [Theory]
    [InlineData(@".\Users\Alice\Doc.txt", @"Users\Alice\Doc.txt")]
    [InlineData(@"Users/Alice//Doc.txt", @"Users\Alice\Doc.txt")]
    [InlineData(@"(unresolved)", null)]
    [InlineData("", null)]
    public void NormalizePath_HandlesMixedPathShapes(string raw, string? expected)
    {
        var actual = CandidateTreeBuilder.NormalizePath(raw);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Build_CreatesNestedTreeAndPreservesDuplicateLeafCandidates()
    {
        var nodes = CandidateTreeBuilder.Build(
        [
            new CandidateTreeEntry("a", "Doc.txt", @"Users\Alice\Doc.txt", IsDirectory: false),
            new CandidateTreeEntry("b", "Doc.txt", @"Users\Alice\Doc.txt", IsDirectory: false),
            new CandidateTreeEntry("c", "Pic.jpg", @"Users\Alice\Pics\Pic.jpg", IsDirectory: false),
            new CandidateTreeEntry("d", "alice", @"Users\Alice", IsDirectory: true),
        ]);

        var users = Assert.Single(nodes);
        Assert.Equal("Users", users.DisplayName);
        Assert.True(users.IsFolder);

        var alice = Assert.Single(users.Children);
        Assert.Equal("Alice", alice.DisplayName);
        Assert.True(alice.IsFolder);

        var doc = alice.Children.FirstOrDefault(node => node.DisplayName.Equals("Doc.txt", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(doc);
        Assert.False(doc!.IsFolder);
        Assert.Equal(2, doc.CandidateKeys.Count);
        Assert.Contains("a", doc.CandidateKeys);
        Assert.Contains("b", doc.CandidateKeys);
    }

    [Fact]
    public void Build_PlacesMissingPathsUnderUnresolvedRoot()
    {
        var nodes = CandidateTreeBuilder.Build(
        [
            new CandidateTreeEntry("x", "LostFile.bin", null, IsDirectory: false),
        ]);

        var unresolved = Assert.Single(nodes);
        Assert.Equal(CandidateTreeBuilder.UnresolvedRootName, unresolved.DisplayName);
        Assert.True(unresolved.IsFolder);
        var child = Assert.Single(unresolved.Children);
        Assert.Equal("LostFile.bin", child.DisplayName);
        Assert.False(child.IsFolder);
        Assert.Contains("x", child.CandidateKeys);
    }

    [Fact]
    public void Build_UsesFilteredSubsetProjectionForVisibleBranches()
    {
        var entries = new[]
        {
            new CandidateTreeEntry("a", "Report.docx", @"Users\Alice\Docs\Report.docx", IsDirectory: false),
            new CandidateTreeEntry("b", "Photo.jpg", @"Users\Alice\Pics\Photo.jpg", IsDirectory: false),
        };

        var filteredNodes = CandidateTreeBuilder.Build(
            entries.Where(entry => entry.CandidateKey == "a"));

        var users = Assert.Single(filteredNodes);
        var alice = Assert.Single(users.Children);
        var docs = Assert.Single(alice.Children);
        Assert.Equal("Docs", docs.DisplayName);
        var report = Assert.Single(docs.Children);
        Assert.Equal("Report.docx", report.DisplayName);
        Assert.DoesNotContain(alice.Children, node => node.DisplayName.Equals("Pics", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CollectRecoverableCandidateKeys_FolderSelectionIncludesRecoverableDescendantsOnly()
    {
        var nodes = CandidateTreeBuilder.Build(
        [
            new CandidateTreeEntry("keep-a", "DocA.txt", @"Users\Alice\Docs\DocA.txt", IsDirectory: false),
            new CandidateTreeEntry("skip-b", "DocB.txt", @"Users\Alice\Docs\DocB.txt", IsDirectory: false),
            new CandidateTreeEntry("keep-c", "PicC.jpg", @"Users\Alice\Pics\PicC.jpg", IsDirectory: false),
        ]);

        var users = Assert.Single(nodes);
        var recoverable = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "keep-a",
            "keep-c",
        };

        var selected = CandidateTreeBuilder.CollectRecoverableCandidateKeys(users, recoverable);
        Assert.Equal(2, selected.Count);
        Assert.Contains("keep-a", selected);
        Assert.Contains("keep-c", selected);
        Assert.DoesNotContain("skip-b", selected);

        var deselectScope = CandidateTreeBuilder.CollectCandidateKeys(users);
        Assert.Equal(3, deselectScope.Count);
    }
}
