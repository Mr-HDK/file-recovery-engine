using FileRecovery.WindowsApp.Core.Services;

namespace FileRecovery.WindowsApp.Tests;

public sealed class CandidateBrowserViewStateTests
{
    [Fact]
    public void ResolveMode_ForcesGridWhenNoCandidates()
    {
        var resolved = CandidateBrowserViewState.ResolveMode(
            CandidateBrowserViewMode.Tree,
            totalCandidateCount: 0);

        Assert.Equal(CandidateBrowserViewMode.Grid, resolved);
        Assert.False(CandidateBrowserViewState.IsTreeEnabled(totalCandidateCount: 0));
    }

    [Fact]
    public void ResolveMode_KeepsRequestedModeWhenCandidatesExist()
    {
        var resolved = CandidateBrowserViewState.ResolveMode(
            CandidateBrowserViewMode.Tree,
            totalCandidateCount: 3);

        Assert.Equal(CandidateBrowserViewMode.Tree, resolved);
        Assert.True(CandidateBrowserViewState.IsTreeEnabled(totalCandidateCount: 3));
    }

    [Theory]
    [InlineData(0, 0, "Run a scan to populate Source File Browser tree.")]
    [InlineData(4, 0, "No candidates match current filters for tree view.")]
    [InlineData(4, 2, null)]
    public void BuildHintText_MatchesCandidateAndTreeState(
        int totalCandidates,
        int treeNodes,
        string? expected)
    {
        var hint = CandidateBrowserViewState.BuildHintText(totalCandidates, treeNodes);
        Assert.Equal(expected, hint);
    }
}
