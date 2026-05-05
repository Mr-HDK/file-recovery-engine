namespace FileRecovery.WindowsApp.Core.Services;

public enum CandidateBrowserViewMode
{
    Grid,
    Tree,
}

public static class CandidateBrowserViewState
{
    public static bool IsTreeEnabled(int totalCandidateCount)
    {
        return totalCandidateCount > 0;
    }

    public static CandidateBrowserViewMode ResolveMode(
        CandidateBrowserViewMode requestedMode,
        int totalCandidateCount)
    {
        if (!IsTreeEnabled(totalCandidateCount))
        {
            return CandidateBrowserViewMode.Grid;
        }

        return requestedMode;
    }

    public static string? BuildHintText(int totalCandidateCount, int treeNodeCount)
    {
        if (totalCandidateCount <= 0)
        {
            return "Run a scan to populate Source File Browser tree.";
        }

        if (treeNodeCount <= 0)
        {
            return "No candidates match current filters for tree view.";
        }

        return null;
    }
}
