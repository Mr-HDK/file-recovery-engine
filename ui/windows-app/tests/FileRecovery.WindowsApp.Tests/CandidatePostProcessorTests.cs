using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Services;

namespace FileRecovery.WindowsApp.Tests;

public sealed class CandidatePostProcessorTests
{
    [Fact]
    public void Process_DeduplicatesNearIdenticalCandidatesAndMergesEvidence()
    {
        var processor = new CandidatePostProcessor();
        var input = new[]
        {
            new QuickScanCandidateRecord(
                Ordinal: 0,
                RecordNumber: 41,
                Deleted: true,
                Directory: false,
                NonResidentData: true,
                Name: "report.txt",
                OriginalPath: @"Docs\report.txt",
                ParentRecordNumber: 5,
                EvidenceSources: "MFT",
                ConfidenceTier: "High",
                ConfidenceReason: "Metadata-backed"),
            new QuickScanCandidateRecord(
                Ordinal: 1,
                RecordNumber: 777,
                Deleted: true,
                Directory: false,
                NonResidentData: false,
                Name: "report.txt",
                OriginalPath: @"Docs\report.txt",
                ParentRecordNumber: 5,
                EvidenceSources: "USN",
                ConfidenceTier: "Medium",
                ConfidenceReason: "Journal-assisted"),
        };

        var result = processor.Process(input);

        var single = Assert.Single(result.Candidates);
        Assert.Equal(2, result.InputCount);
        Assert.Equal(1, result.ClusterCount);
        Assert.Equal(1, result.RemovedDuplicateCount);
        Assert.Equal(2, single.ClusterSize);
        Assert.Equal(1, single.DeduplicatedCount);
        Assert.Contains("MFT", single.Candidate.EvidenceSources);
        Assert.Contains("USN", single.Candidate.EvidenceSources);
        Assert.Contains("Cluster", single.Candidate.ConfidenceReason);
    }

    [Fact]
    public void Process_AssignsPlaceholderNameAndPath_WhenOriginalMetadataMissing()
    {
        var processor = new CandidatePostProcessor();
        var input = new[]
        {
            new QuickScanCandidateRecord(
                Ordinal: 0,
                RecordNumber: 512,
                Deleted: true,
                Directory: false,
                NonResidentData: false,
                Name: "(unknown)",
                OriginalPath: "(unresolved)",
                ParentRecordNumber: null,
                EvidenceSources: "MFT",
                ConfidenceTier: "Medium",
                ConfidenceReason: "Candidate missing name/path"),
        };

        var result = processor.Process(input);
        var candidate = Assert.Single(result.Candidates).Candidate;

        Assert.Equal("file-record-512.bin", candidate.Name);
        Assert.Equal(@"Recovered\file-record-512.bin", candidate.OriginalPath);
    }

    [Fact]
    public void Process_UsesMetadataHintForCarveCandidateRenameHeuristic()
    {
        var processor = new CandidatePostProcessor();
        var input = new[]
        {
            new QuickScanCandidateRecord(
                Ordinal: 0,
                RecordNumber: 9001,
                Deleted: false,
                Directory: false,
                NonResidentData: false,
                Name: "carve_0011223344.docx",
                OriginalPath: @"Carved\carve_0011223344.docx",
                ParentRecordNumber: null,
                EvidenceSources: "Carve",
                ConfidenceTier: "Low",
                ConfidenceReason: "title=Quarterly Budget 2026",
                CarveFormat: "docx"),
        };

        var result = processor.Process(input);
        var candidate = Assert.Single(result.Candidates).Candidate;

        Assert.Equal("carve-quarterly-budget-2026.docx", candidate.Name);
        Assert.Equal(@"Carved\carve-quarterly-budget-2026.docx", candidate.OriginalPath);
    }
}
