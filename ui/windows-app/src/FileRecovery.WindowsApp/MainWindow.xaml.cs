using FileRecovery.WindowsApp.Core.Engine;
using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Persistence;
using FileRecovery.WindowsApp.Core.Services;
using Microsoft.Win32;
using System.ComponentModel;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using WinForms = System.Windows.Forms;

namespace FileRecovery.WindowsApp;

public partial class MainWindow : Window
{
    private sealed class QuickScanCandidateRow
    {
        public int Ordinal { get; init; }
        public bool IsSelected { get; set; }
        public uint RecordNumber { get; init; }
        public bool Deleted { get; init; }
        public bool IsGhostRecord { get; init; }
        public bool Directory { get; init; }
        public bool NonResidentData { get; init; }
        public bool HasNamedDataStreams { get; init; }
        public bool IsCompressed { get; init; }
        public bool IsSparse { get; init; }
        public bool IsEncrypted { get; init; }
        public string Name { get; init; } = string.Empty;
        public string OriginalPath { get; init; } = string.Empty;
        public string ParentRecord { get; init; } = string.Empty;
        public ulong? DataSizeBytes { get; init; }
        public ulong? AllocatedSizeBytes { get; init; }
        public uint? FileAttributes { get; init; }
        public ulong? CreatedFileTimeUtc { get; init; }
        public ulong? ModifiedFileTimeUtc { get; init; }
        public ulong? MftModifiedFileTimeUtc { get; init; }
        public ulong? AccessedFileTimeUtc { get; init; }
        public string DataSizeDisplay => DataSizeBytes.HasValue
            ? DataSizeBytes.Value.ToString(CultureInfo.InvariantCulture)
            : string.Empty;
        public string ModifiedUtcDisplay => FormatFileTimeUtc(ModifiedFileTimeUtc);
        public string FileAttributesDisplay => FileAttributes.HasValue
            ? $"0x{FileAttributes.Value:X8}"
            : string.Empty;
        public string EvidenceSource { get; init; } = "MFT";
        public string ConfidenceTier { get; init; } = "Medium";
        public RecoveryCandidateStatus CandidateStatus { get; set; } = RecoveryCandidateStatus.Partial;
        public string CandidateStatusCode => CandidateStatus.ToStorageCode();
        public string ConfidenceReason { get; init; } = string.Empty;
        public int? LastRecoveryStatusCode { get; set; }
        public uint? LastRecoveryDiagnosticsFlags { get; set; }
        public ulong? LastRecoveredBytes { get; set; }
        public bool? LastRecoveryPartial { get; set; }
        public string RecoveryDiagnostics { get; set; } = string.Empty;
        public string RecoveryStatusCodeDisplay =>
            LastRecoveryStatusCode.HasValue
                ? LastRecoveryStatusCode.Value.ToString(CultureInfo.InvariantCulture)
                : string.Empty;
        public string RecoveryDiagnosticsFlagsDisplay =>
            LastRecoveryDiagnosticsFlags.HasValue
                ? $"0x{LastRecoveryDiagnosticsFlags.Value:X8}"
                : string.Empty;

        private static string FormatFileTimeUtc(ulong? fileTime)
        {
            if (!fileTime.HasValue || fileTime.Value == 0)
            {
                return string.Empty;
            }

            if (fileTime.Value > long.MaxValue)
            {
                return string.Empty;
            }

            try
            {
                return DateTimeOffset
                    .FromFileTime((long)fileTime.Value)
                    .UtcDateTime
                    .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
            }
            catch
            {
                return string.Empty;
            }
        }
    }

    private readonly IDeviceEnumerationService _deviceEnumerationService;
    private readonly SourceDestinationSafetyValidator _safetyValidator;
    private readonly IPrivilegeService _privilegeService;
    private readonly SqliteSessionStore _sessionStore;
    private readonly SessionLogWriter _sessionLogWriter;
    private readonly ReadPreviewScanner _previewScanner;
    private readonly ObservableCollection<SourceCandidate> _sources = [];
    private readonly ObservableCollection<string> _validationOutput = [];
    private readonly ObservableCollection<QuickScanCandidateRow> _quickScanCandidates = [];
    private readonly ObservableCollection<string> _candidateActivity = [];
    private static readonly TimeSpan SessionRetentionAge = TimeSpan.FromDays(30);
    private const string UiBuildTag = "ui-scroll-fix-20260328-0006";
    private const int MaxUiActivityLogEntries = 400;
    private const int SessionRetentionMaxCount = 50;
    private SourceCandidate? _selectedSource;
    private ICollectionView? _quickScanCandidatesView;
    private CancellationTokenSource? _previewReadCts;
    private CancellationTokenSource? _refreshCts;
    private CancellationTokenSource? _operationCts;
    private Guid? _activeSessionId;
    private bool _isElevated;
    private bool _elevationWarningLogged;
    private bool _filterDeletedOnly;
    private bool _filterRecoverableOnly;
    private bool _filterSelectedOnly;
    private string _candidateSearchTerm = string.Empty;

    public MainWindow()
    {
        InitializeComponent();

        var topology = new WindowsStorageTopologyService();
        _deviceEnumerationService = new WindowsDeviceEnumerationService(topology);
        _safetyValidator = new SourceDestinationSafetyValidator(topology);
        _privilegeService = new WindowsPrivilegeService();
        _sessionStore = new SqliteSessionStore();
        _sessionLogWriter = new SessionLogWriter();
        _previewScanner = new ReadPreviewScanner();

        SourcesDataGrid.ItemsSource = _sources;
        ValidationListBox.ItemsSource = _validationOutput;
        CandidateActivityListBox.ItemsSource = _candidateActivity;

        _quickScanCandidates.CollectionChanged += (_, _) => UpdateCandidateSummary();
        _quickScanCandidatesView = CollectionViewSource.GetDefaultView(_quickScanCandidates);
        _quickScanCandidatesView.Filter = FilterQuickScanCandidate;
        QuickScanCandidatesDataGrid.ItemsSource = _quickScanCandidatesView;

        ScanModeComboBox.ItemsSource = Enum.GetValues<ScanMode>();
        ScanModeComboBox.SelectedItem = ScanMode.Quick;
        UpdateCandidateSummary();

        var version = NativeEngineProbe.GetVersionDisplay();
        var health = NativeEngineProbe.IsHealthy() ? "healthy" : "mock";
        EngineStatusTextBlock.Text = $"Engine: {version} ({health})";

        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            RefreshElevationState();
            await _sessionStore.EnsureCreatedAsync(CancellationToken.None);
            await RunSessionStoreMaintenanceAsync(userInitiated: false, compactDatabase: false, CancellationToken.None);
            await RefreshSourcesAsync(CancellationToken.None);
            await LoadLatestPersistedCandidatesAsync(CancellationToken.None);
            AppendSessionMessage($"UI build: {UiBuildTag}");
            AppendSessionMessage($"Session DB: {_sessionStore.DatabasePath}");
            StatusTextBlock.Text = "Ready";
        }
        catch (Exception ex)
        {
            StatusTextBlock.Text = "Initialization failed";
            AppendSessionMessage($"Initialization error: {ex.Message}");
        }
    }

    private async void RefreshSourcesButton_Click(object sender, RoutedEventArgs e)
    {
        _refreshCts?.Cancel();
        _refreshCts?.Dispose();
        _refreshCts = new CancellationTokenSource();

        await RefreshSourcesAsync(_refreshCts.Token);
    }

    private async Task RefreshSourcesAsync(CancellationToken cancellationToken)
    {
        StatusTextBlock.Text = "Enumerating sources...";
        _sources.Clear();

        try
        {
            var result = await _deviceEnumerationService.EnumerateAsync(cancellationToken);
            foreach (var source in result.Sources)
            {
                _sources.Add(source);
            }

            if (_sources.Count > 0)
            {
                SourcesDataGrid.SelectedIndex = 0;
            }

            foreach (var warning in result.Warnings)
            {
                AppendSessionMessage($"Enumeration warning: {warning}");
            }

            StatusTextBlock.Text = $"Found {_sources.Count} sources";
        }
        catch (OperationCanceledException)
        {
            StatusTextBlock.Text = "Source enumeration canceled";
            AppendSessionMessage("Source enumeration canceled.");
        }
        catch (Exception ex)
        {
            StatusTextBlock.Text = "Source enumeration failed";
            AppendSessionMessage($"Enumeration error: {ex.Message}");
        }
    }

    private void SourcesDataGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _selectedSource = SourcesDataGrid.SelectedItem as SourceCandidate;
    }

    private async void ImportImageButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Image Files (*.img;*.dd;*.raw)|*.img;*.dd;*.raw|All Files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var image = await _deviceEnumerationService.BuildImageSourceAsync(dialog.FileName, CancellationToken.None);
            _sources.Insert(0, image);
            SourcesDataGrid.SelectedIndex = 0;
            AppendSessionMessage($"Imported image source: {image.SourcePath}");
            StatusTextBlock.Text = "Image source imported";
        }
        catch (Exception ex)
        {
            StatusTextBlock.Text = "Image import failed";
            AppendSessionMessage($"Image import error: {ex.Message}");
        }
    }

    private void BrowseDestinationButton_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new WinForms.FolderBrowserDialog
        {
            Description = "Select destination folder on a different disk or volume",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
        };

        if (dialog.ShowDialog() == WinForms.DialogResult.OK)
        {
            DestinationPathTextBox.Text = dialog.SelectedPath;
        }
    }

    private void ValidateSafetyButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshElevationState();
        var result = _safetyValidator.Validate(_selectedSource, DestinationPathTextBox.Text, _isElevated);
        RenderValidation(result);
    }

    private async void StartSessionButton_Click(object sender, RoutedEventArgs e)
    {
        _quickScanCandidates.Clear();
        var operationScope = StartNewOperationScope();
        var operationToken = operationScope.Token;

        RefreshElevationState();
        var validation = _safetyValidator.Validate(_selectedSource, DestinationPathTextBox.Text, _isElevated);
        RenderValidation(validation);

        if (!validation.IsValid || _selectedSource is null)
        {
            StatusTextBlock.Text = "Session blocked by safety validation";
            return;
        }

        var selectedSource = _selectedSource;
        EngineNtfsQuickScanCandidatesResult? quickScanCandidates = null;
        Guid? sessionId = null;

        try
        {
            operationToken.ThrowIfCancellationRequested();

            var probePath = ResolveProbePath(selectedSource);
            if (!string.IsNullOrWhiteSpace(probePath))
            {
                operationToken.ThrowIfCancellationRequested();
                var open = NativeEngineProbe.OpenSourceReadOnlySession(probePath, selectedSource.Kind);
                AppendSessionMessage(
                    $"Engine session open: {open.Message} (status {open.StatusCode}, alignment {open.AlignmentBytes}).");

                if (open.EngineAvailable && !open.Opened)
                {
                    _validationOutput.Add($"Error: Engine failed read-only source open ({open.Message}).");
                    StatusTextBlock.Text = "Session blocked by engine read-only open";
                    return;
                }

                if (!open.EngineAvailable)
                {
                    _validationOutput.Add("Warning: Native engine unavailable; proceeding with UI-only safety checks.");
                }
                else
                {
                    try
                    {
                        operationToken.ThrowIfCancellationRequested();
                        var preflightBufferSize = GetAlignedBufferLength(open.AlignmentBytes, 4096);
                        var preflightBuffer = new byte[preflightBufferSize];
                        var read = NativeEngineProbe.ReadSourceSessionChunk(open.SessionId, 0, preflightBuffer);
                        AppendSessionMessage($"Engine preflight read: {read.Message} (status {read.StatusCode}, bytes {read.BytesRead}).");

                        if (!read.Success)
                        {
                            _validationOutput.Add($"Error: Engine preflight read failed ({read.Message}).");
                            StatusTextBlock.Text = "Session blocked by engine preflight read";
                            return;
                        }

                        operationToken.ThrowIfCancellationRequested();
                        var ntfsBoot = NativeEngineProbe.ProbeNtfsBootFromSession(open.SessionId);
                        AppendSessionMessage($"NTFS boot probe: {ntfsBoot.Message} (status {ntfsBoot.StatusCode}).");

                        if (ntfsBoot.Success && ntfsBoot.Metadata is not null)
                        {
                            var metadata = ntfsBoot.Metadata;
                            AppendSessionMessage(
                                $"NTFS boot details: sector={metadata.BytesPerSector}, cluster={metadata.ClusterSizeBytes}, MFT offset={metadata.MftOffsetBytes}.");

                            operationToken.ThrowIfCancellationRequested();
                            var quickScan = NativeEngineProbe.QuickScanNtfsFromSession(open.SessionId, maxRecords: 256);
                            AppendSessionMessage(
                $"NTFS quick scan: {quickScan.Message} (status {quickScan.StatusCode}, parsed={quickScan.ParsedRecords}, failures={quickScan.ParseFailures}, deleted={quickScan.DeletedRecords}, dirs={quickScan.DirectoryRecords}, named={quickScan.NamedRecords}, resident={quickScan.ResidentAttributeCount}, nonresident={quickScan.NonResidentAttributeCount}, nonresident-data={quickScan.RecordsWithNonResidentData}).");
                            AppendSessionMessage(
                                $"NTFS quick scan USN enrichment: matched={quickScan.UsnEnrichedRecords}, ghost={quickScan.UsnGhostRecords}.");

                            if (quickScan.Success)
                            {
                                operationToken.ThrowIfCancellationRequested();
                                var candidateResult = NativeEngineProbe.GetNtfsQuickScanCandidatesFromSession(
                                    open.SessionId,
                                    maxRecords: 256,
                                    candidateCapacity: 128);

                                AppendSessionMessage(
                                    $"NTFS quick scan candidates: {candidateResult.Message} (status {candidateResult.StatusCode}, count={candidateResult.Candidates.Count}).");
                                RenderQuickScanCandidates(candidateResult);
                                quickScanCandidates = candidateResult;
                            }
                        }
                    }
                    finally
                    {
                        var closeStatus = NativeEngineProbe.CloseSourceSession(open.SessionId);
                        AppendSessionMessage($"Engine session close status: {closeStatus}");
                    }
                }
            }

            var scanMode = ScanModeComboBox.SelectedItem is ScanMode mode ? mode : ScanMode.Quick;
            operationToken.ThrowIfCancellationRequested();
            sessionId = await _sessionStore.CreateSessionAsync(
                selectedSource,
                DestinationPathTextBox.Text,
                scanMode,
                operationToken);
            _activeSessionId = sessionId.Value;

            await _sessionLogWriter.CreateSessionLogsAsync(sessionId.Value, operationToken);
            await _sessionLogWriter.LogEventAsync(sessionId.Value, "session_initialized", new
            {
                source_id = selectedSource.Id,
                source_kind = selectedSource.Kind.ToString(),
                destination = DestinationPathTextBox.Text,
                scan_mode = scanMode.ToString(),
            }, operationToken);

            await _sessionLogWriter.LogMessageAsync(sessionId.Value, "Session created and waiting for scan pipeline execution.", operationToken);
            await _sessionStore.UpdateStatusAsync(sessionId.Value, "ready", "Session initialized by UI.", operationToken);

            if (quickScanCandidates?.Success == true)
            {
                operationToken.ThrowIfCancellationRequested();
                var candidateRows = quickScanCandidates.Candidates
                    .Select((candidate, index) => new QuickScanCandidateRecord(
                        Ordinal: index,
                        RecordNumber: candidate.RecordNumber,
                        Deleted: candidate.Deleted,
                        IsGhostRecord: candidate.IsGhostRecord,
                        Directory: candidate.IsDirectory,
                        NonResidentData: candidate.HasNonResidentData,
                        HasNamedDataStreams: candidate.HasNamedDataStreams,
                        IsCompressed: candidate.IsCompressed,
                        IsSparse: candidate.IsSparse,
                        IsEncrypted: candidate.IsEncrypted,
                        Name: candidate.Name,
                        OriginalPath: candidate.ReconstructedPath,
                        ParentRecordNumber: candidate.ParentRecordNumber,
                        DataSizeBytes: candidate.DataSizeBytes,
                        AllocatedSizeBytes: candidate.AllocatedSizeBytes,
                        FileAttributes: candidate.FileAttributes,
                        CreatedFileTimeUtc: candidate.CreatedFileTimeUtc,
                        ModifiedFileTimeUtc: candidate.ModifiedFileTimeUtc,
                        MftModifiedFileTimeUtc: candidate.MftModifiedFileTimeUtc,
                        AccessedFileTimeUtc: candidate.AccessedFileTimeUtc,
                        EvidenceSources: candidate.EvidenceSources,
                        ConfidenceTier: candidate.ConfidenceTier,
                        ConfidenceReason: candidate.ConfidenceReason,
                        CandidateStatus: ComputeCandidateStatus(
                            candidate.Deleted,
                            candidate.IsGhostRecord,
                            candidate.IsDirectory,
                            candidate.IsCompressed,
                            candidate.IsEncrypted,
                            candidate.HasNamedDataStreams,
                            candidate.Name,
                            candidate.ReconstructedPath)))
                    .ToArray();

                await _sessionStore.ReplaceQuickScanCandidatesAsync(sessionId.Value, candidateRows, operationToken);
                await _sessionLogWriter.LogEventAsync(sessionId.Value, "quick_scan_candidates_persisted", new
                {
                    count = candidateRows.Length,
                }, operationToken);

                var persisted = await _sessionStore.GetQuickScanCandidatesAsync(sessionId.Value, 256, operationToken);
                RenderQuickScanCandidates(persisted);
                AppendSessionMessage($"Persisted quick-scan candidates: {persisted.Count}.");
            }

            AppendSessionMessage($"Session {sessionId.Value:D} initialized.");
            StatusTextBlock.Text = "Session initialized";

            if (NativeEngineProbe.IsHealthy())
            {
                await RunPreviewReadAsync(selectedSource, sessionId.Value);
            }
            else
            {
                AppendSessionMessage("Skipping preview read because native engine is unavailable.");
            }
        }
        catch (OperationCanceledException)
        {
            StatusTextBlock.Text = "Session initialization canceled";
            AppendSessionMessage("Session initialization canceled.");

            if (sessionId.HasValue)
            {
                await TryMarkSessionCanceledAsync(sessionId.Value, "Session initialization canceled.");
            }
        }
        catch (Exception ex)
        {
            StatusTextBlock.Text = "Failed to create session";
            AppendSessionMessage($"Session creation error: {ex.Message}");

            if (sessionId.HasValue)
            {
                await TryMarkSessionFailedAsync(sessionId.Value, "error", ex.Message, null);
            }
        }
        finally
        {
            CompleteOperationScope(operationScope);
        }
    }

    private void RenderValidation(ValidationResult result)
    {
        _validationOutput.Clear();

        foreach (var issue in result.Issues)
        {
            _validationOutput.Add($"{issue.Severity}: {issue.Message}");
        }

        if (result.Issues.Count == 0)
        {
            _validationOutput.Add("No validation messages.");
        }

        var summary = new StringBuilder();
        summary.Append("Validation completed. ");
        summary.Append(result.IsValid ? "Safe to initialize session." : "Blocked until issues are fixed.");
        AppendSessionMessage(summary.ToString());
    }

    private void RenderQuickScanCandidates(EngineNtfsQuickScanCandidatesResult result)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            RefreshCandidateView();
            AppendCandidateActivity("Candidate load failed: engine result was not successful.");
            return;
        }

        var mapped = result.Candidates
            .Select((candidate, index) => new QuickScanCandidateRecord(
                Ordinal: index,
                RecordNumber: candidate.RecordNumber,
                Deleted: candidate.Deleted,
                IsGhostRecord: candidate.IsGhostRecord,
                Directory: candidate.IsDirectory,
                NonResidentData: candidate.HasNonResidentData,
                HasNamedDataStreams: candidate.HasNamedDataStreams,
                IsCompressed: candidate.IsCompressed,
                IsSparse: candidate.IsSparse,
                IsEncrypted: candidate.IsEncrypted,
                Name: candidate.Name,
                OriginalPath: candidate.ReconstructedPath,
                ParentRecordNumber: candidate.ParentRecordNumber,
                DataSizeBytes: candidate.DataSizeBytes,
                AllocatedSizeBytes: candidate.AllocatedSizeBytes,
                FileAttributes: candidate.FileAttributes,
                CreatedFileTimeUtc: candidate.CreatedFileTimeUtc,
                ModifiedFileTimeUtc: candidate.ModifiedFileTimeUtc,
                MftModifiedFileTimeUtc: candidate.MftModifiedFileTimeUtc,
                AccessedFileTimeUtc: candidate.AccessedFileTimeUtc,
                EvidenceSources: candidate.EvidenceSources,
                ConfidenceTier: candidate.ConfidenceTier,
                ConfidenceReason: candidate.ConfidenceReason,
                CandidateStatus: ComputeCandidateStatus(
                    candidate.Deleted,
                    candidate.IsGhostRecord,
                    candidate.IsDirectory,
                    candidate.IsCompressed,
                    candidate.IsEncrypted,
                    candidate.HasNamedDataStreams,
                    candidate.Name,
                    candidate.ReconstructedPath)))
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(IReadOnlyList<QuickScanCandidateRecord> candidates)
    {
        _quickScanCandidates.Clear();

        foreach (var candidate in candidates)
        {
            _quickScanCandidates.Add(new QuickScanCandidateRow
            {
                Ordinal = candidate.Ordinal,
                IsSelected = candidate.Deleted && !candidate.IsGhostRecord,
                RecordNumber = candidate.RecordNumber,
                Deleted = candidate.Deleted,
                IsGhostRecord = candidate.IsGhostRecord,
                Directory = candidate.Directory,
                NonResidentData = candidate.NonResidentData,
                HasNamedDataStreams = candidate.HasNamedDataStreams,
                IsCompressed = candidate.IsCompressed,
                IsSparse = candidate.IsSparse,
                IsEncrypted = candidate.IsEncrypted,
                Name = candidate.Name ?? "(unknown)",
                OriginalPath = candidate.OriginalPath ?? "(unresolved)",
                ParentRecord = candidate.ParentRecordNumber?.ToString() ?? string.Empty,
                DataSizeBytes = candidate.DataSizeBytes,
                AllocatedSizeBytes = candidate.AllocatedSizeBytes,
                FileAttributes = candidate.FileAttributes,
                CreatedFileTimeUtc = candidate.CreatedFileTimeUtc,
                ModifiedFileTimeUtc = candidate.ModifiedFileTimeUtc,
                MftModifiedFileTimeUtc = candidate.MftModifiedFileTimeUtc,
                AccessedFileTimeUtc = candidate.AccessedFileTimeUtc,
                EvidenceSource = candidate.EvidenceSources,
                ConfidenceTier = candidate.ConfidenceTier,
                CandidateStatus = candidate.CandidateStatus,
                ConfidenceReason = candidate.ConfidenceReason,
                LastRecoveryStatusCode = candidate.LastRecoveryStatusCode,
                LastRecoveryDiagnosticsFlags = candidate.LastRecoveryDiagnosticsFlags,
                LastRecoveredBytes = candidate.LastRecoveredBytes,
                LastRecoveryPartial = candidate.LastRecoveryPartial,
                RecoveryDiagnostics = candidate.RecoveryDiagnostics ?? string.Empty,
            });
        }

        RefreshCandidateView();
        AppendCandidateActivity($"Loaded {_quickScanCandidates.Count} candidate rows.");
    }

    private bool FilterQuickScanCandidate(object rowObject)
    {
        if (rowObject is not QuickScanCandidateRow row)
        {
            return false;
        }

        if (_filterDeletedOnly && !row.Deleted)
        {
            return false;
        }

        if (_filterRecoverableOnly && !IsRecoverableCandidate(row))
        {
            return false;
        }

        if (_filterSelectedOnly && !row.IsSelected)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(_candidateSearchTerm))
        {
            return true;
        }

        return row.Name.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.OriginalPath.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.RecordNumber.ToString(CultureInfo.InvariantCulture).Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.DataSizeDisplay.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.ModifiedUtcDisplay.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.FileAttributesDisplay.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.EvidenceSource.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.CandidateStatusCode.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.RecoveryDiagnostics.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRecoverableCandidate(QuickScanCandidateRow row)
    {
        return !row.Directory && !row.IsGhostRecord && row.CandidateStatus != RecoveryCandidateStatus.Invalid;
    }

    private void RefreshCandidateView()
    {
        _quickScanCandidatesView?.Refresh();
        UpdateCandidateSummary();
    }

    private void UpdateCandidateSummary()
    {
        var total = _quickScanCandidates.Count;
        var selected = _quickScanCandidates.Count(candidate => candidate.IsSelected);
        var deleted = _quickScanCandidates.Count(candidate => candidate.Deleted);
        var recoverable = _quickScanCandidates.Count(IsRecoverableCandidate);
        var visible = _quickScanCandidatesView?.Cast<object>().Count() ?? total;

        CandidateSummaryTextBlock.Text =
            $"Visible {visible}/{total} | Selected {selected} | Deleted {deleted} | Recoverable {recoverable}";
    }

    private void AppendCandidateActivity(string message)
    {
        var line = $"[{DateTimeOffset.Now:HH:mm:ss}] {message}";
        _candidateActivity.Add(line);

        while (_candidateActivity.Count > MaxUiActivityLogEntries)
        {
            _candidateActivity.RemoveAt(0);
        }

        if (_candidateActivity.Count > 0)
        {
            CandidateActivityListBox.ScrollIntoView(_candidateActivity[^1]);
        }
    }

    private static RecoveryCandidateStatus ComputeCandidateStatus(
        bool deleted,
        bool isGhostRecord,
        bool directory,
        bool compressed,
        bool encrypted,
        bool hasNamedDataStreams,
        string? name,
        string? originalPath)
    {
        if (directory || !deleted || isGhostRecord)
        {
            return RecoveryCandidateStatus.Invalid;
        }

        if (encrypted)
        {
            return RecoveryCandidateStatus.Invalid;
        }

        if (compressed || hasNamedDataStreams || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(originalPath))
        {
            return RecoveryCandidateStatus.Partial;
        }

        return RecoveryCandidateStatus.Full;
    }

    private static RecoveryCandidateStatus MapRecoveryFailureStatus(int statusCode)
    {
        return statusCode switch
        {
            41 => RecoveryCandidateStatus.OverwrittenRisk,
            _ => RecoveryCandidateStatus.Invalid,
        };
    }

    private async Task LoadLatestPersistedCandidatesAsync(CancellationToken cancellationToken)
    {
        var sessions = await _sessionStore.GetRecentSessionsAsync(1, cancellationToken);
        var latest = sessions.FirstOrDefault();
        if (latest is null)
        {
            return;
        }

        var persisted = await _sessionStore.GetQuickScanCandidatesAsync(latest.SessionId, 256, cancellationToken);
        if (persisted.Count == 0)
        {
            return;
        }

        _activeSessionId = latest.SessionId;
        RenderQuickScanCandidates(persisted);
        AppendSessionMessage($"Loaded {persisted.Count} persisted quick-scan candidates from session {latest.SessionId:D}.");
    }

    private async void SessionMaintenanceButton_Click(object sender, RoutedEventArgs e)
    {
        await RunSessionStoreMaintenanceAsync(userInitiated: true, compactDatabase: true, CancellationToken.None);
    }

    private async Task RunSessionStoreMaintenanceAsync(
        bool userInitiated,
        bool compactDatabase,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await _sessionStore.ApplyRetentionPolicyAsync(
                SessionRetentionAge,
                SessionRetentionMaxCount,
                compactDatabase,
                cancellationToken);

            AppendSessionMessage(
                $"Session DB maintenance: deleted-old={result.DeletedByAge}, deleted-overflow={result.DeletedByOverflow}, remaining={result.RemainingSessions}, compacted={(result.Compacted ? "yes" : "no")}.");

            if (userInitiated)
            {
                StatusTextBlock.Text = "Session DB maintenance completed";
            }
        }
        catch (OperationCanceledException)
        {
            AppendSessionMessage("Session DB maintenance canceled.");
            if (userInitiated)
            {
                StatusTextBlock.Text = "Session DB maintenance canceled";
            }
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Session DB maintenance warning: {ex.Message}");
            if (userInitiated)
            {
                StatusTextBlock.Text = "Session DB maintenance failed";
            }
        }
    }

    private void CopySessionLogButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Windows.Clipboard.SetText(SessionOutputTextBox.Text ?? string.Empty);
            StatusTextBlock.Text = "Session log copied";
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Session log copy failed: {ex.Message}");
            StatusTextBlock.Text = "Session log copy failed";
        }
    }

    private void ClearSessionLogButton_Click(object sender, RoutedEventArgs e)
    {
        SessionOutputTextBox.Clear();
        StatusTextBlock.Text = "Session log cleared";
    }

    private void CopyCandidateActivityButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            System.Windows.Clipboard.SetText(string.Join(Environment.NewLine, _candidateActivity));
            StatusTextBlock.Text = "Table activity copied";
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Table activity copy failed: {ex.Message}");
            StatusTextBlock.Text = "Table activity copy failed";
        }
    }

    private void ClearCandidateActivityButton_Click(object sender, RoutedEventArgs e)
    {
        _candidateActivity.Clear();
        StatusTextBlock.Text = "Table activity cleared";
    }

    private void CandidateFilterChanged(object sender, RoutedEventArgs e)
    {
        _filterDeletedOnly = FilterDeletedCheckBox.IsChecked == true;
        _filterRecoverableOnly = FilterRecoverableCheckBox.IsChecked == true;
        _filterSelectedOnly = FilterSelectedCheckBox.IsChecked == true;
        RefreshCandidateView();
        AppendCandidateActivity("Candidate filters updated.");
    }

    private void CandidateSearchTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        _candidateSearchTerm = CandidateSearchTextBox.Text.Trim();
        RefreshCandidateView();
    }

    private void ResetCandidateFiltersButton_Click(object sender, RoutedEventArgs e)
    {
        FilterDeletedCheckBox.IsChecked = false;
        FilterRecoverableCheckBox.IsChecked = false;
        FilterSelectedCheckBox.IsChecked = false;
        CandidateSearchTextBox.Text = string.Empty;
        _filterDeletedOnly = false;
        _filterRecoverableOnly = false;
        _filterSelectedOnly = false;
        _candidateSearchTerm = string.Empty;
        RefreshCandidateView();
        AppendCandidateActivity("Candidate view reset.");
    }

    private void QuickScanCandidatesDataGrid_CellEditEnding(object sender, System.Windows.Controls.DataGridCellEditEndingEventArgs e)
    {
        Dispatcher.BeginInvoke(new Action(RefreshCandidateView), System.Windows.Threading.DispatcherPriority.Background);
    }

    private void QuickScanCandidatesDataGrid_CurrentCellChanged(object? sender, EventArgs e)
    {
        UpdateCandidateSummary();
    }

    private void SelectAllCandidatesButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in _quickScanCandidates)
        {
            row.IsSelected = true;
        }

        RefreshCandidateView();
        AppendSessionMessage($"Selected {_quickScanCandidates.Count} candidates.");
        AppendCandidateActivity($"Selected all {_quickScanCandidates.Count} candidates.");
    }

    private void SelectRecoverableCandidatesButton_Click(object sender, RoutedEventArgs e)
    {
        var selected = 0;
        foreach (var row in _quickScanCandidates)
        {
            row.IsSelected = IsRecoverableCandidate(row);
            if (row.IsSelected)
            {
                selected++;
            }
        }

        RefreshCandidateView();
        AppendSessionMessage($"Selected {selected} recoverable candidates.");
        AppendCandidateActivity($"Selected recoverable candidates: {selected}.");
    }

    private void ClearCandidateSelectionButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in _quickScanCandidates)
        {
            row.IsSelected = false;
        }

        RefreshCandidateView();
        AppendSessionMessage("Candidate selection cleared.");
        AppendCandidateActivity("Selection cleared.");
    }

    private async void ExportSelectedCandidatesButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var selected = _quickScanCandidates.Where(candidate => candidate.IsSelected).ToArray();
            if (selected.Length == 0)
            {
                AppendSessionMessage("No candidates selected for export.");
                AppendCandidateActivity("Export skipped: no candidates selected.");
                return;
            }

            if (string.IsNullOrWhiteSpace(DestinationPathTextBox.Text))
            {
                AppendSessionMessage("Export blocked: destination path is missing.");
                AppendCandidateActivity("Export blocked: destination path missing.");
                return;
            }

            var destination = Path.GetFullPath(DestinationPathTextBox.Text);
            if (!Directory.Exists(destination))
            {
                AppendSessionMessage("Export blocked: destination folder does not exist.");
                AppendCandidateActivity("Export blocked: destination folder does not exist.");
                return;
            }

            var exportDirectory = Path.Combine(destination, "FileRecoveryExports");
            Directory.CreateDirectory(exportDirectory);

            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            var baseName = $"candidates-{stamp}";
            var jsonPath = Path.Combine(exportDirectory, $"{baseName}.json");
            var csvPath = Path.Combine(exportDirectory, $"{baseName}.csv");

            var payload = new
            {
                exported_utc = DateTimeOffset.UtcNow.ToString("O"),
                session_id = _activeSessionId?.ToString("D"),
                source_id = _selectedSource?.Id,
                selected_count = selected.Length,
                candidates = selected.Select(candidate => new
                {
                    record_number = candidate.RecordNumber,
                    deleted = candidate.Deleted,
                    is_ghost_record = candidate.IsGhostRecord,
                    directory = candidate.Directory,
                    non_resident_data = candidate.NonResidentData,
                    has_named_data_streams = candidate.HasNamedDataStreams,
                    compressed = candidate.IsCompressed,
                    sparse = candidate.IsSparse,
                    encrypted = candidate.IsEncrypted,
                    name = candidate.Name,
                    original_path = candidate.OriginalPath,
                    parent_record = candidate.ParentRecord,
                    data_size_bytes = candidate.DataSizeBytes,
                    allocated_size_bytes = candidate.AllocatedSizeBytes,
                    file_attributes = candidate.FileAttributesDisplay,
                    created_filetime_utc = candidate.CreatedFileTimeUtc,
                    modified_filetime_utc = candidate.ModifiedFileTimeUtc,
                    mft_modified_filetime_utc = candidate.MftModifiedFileTimeUtc,
                    accessed_filetime_utc = candidate.AccessedFileTimeUtc,
                    evidence_source = candidate.EvidenceSource,
                    confidence_tier = candidate.ConfidenceTier,
                    confidence_reason = candidate.ConfidenceReason,
                    status = candidate.CandidateStatus.ToStorageCode(),
                    recovery_status_code = candidate.LastRecoveryStatusCode,
                    recovery_diagnostics_flags = candidate.LastRecoveryDiagnosticsFlags,
                    recovered_bytes = candidate.LastRecoveredBytes,
                    recovery_partial = candidate.LastRecoveryPartial,
                    recovery_diagnostics = candidate.RecoveryDiagnostics,
                }),
            };

            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                WriteIndented = true,
            });
            await File.WriteAllTextAsync(jsonPath, json);

            var csv = BuildSelectedCandidatesCsv(selected);
            await File.WriteAllTextAsync(csvPath, csv);

            if (_activeSessionId.HasValue)
            {
                await _sessionLogWriter.LogEventAsync(_activeSessionId.Value, "candidate_export", new
                {
                    selected_count = selected.Length,
                    json_path = jsonPath,
                    csv_path = csvPath,
                }, CancellationToken.None);
            }

            AppendSessionMessage($"Exported {selected.Length} candidates to {jsonPath} and {csvPath}.");
            AppendCandidateActivity($"Exported {selected.Length} candidates.");
            StatusTextBlock.Text = "Candidate export completed";
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Candidate export failed: {ex.Message}");
            AppendCandidateActivity("Candidate export failed.");
            StatusTextBlock.Text = "Candidate export failed";
        }
    }

    private async void RecoverSelectedCandidatesButton_Click(object sender, RoutedEventArgs e)
    {
        var operationScope = StartNewOperationScope();
        var operationToken = operationScope.Token;
        var recovered = 0;
        var partial = 0;
        var failed = 0;
        var overwrittenRisk = 0;
        var selectedCount = 0;
        var recoveryRoot = string.Empty;

        try
        {
            var selected = _quickScanCandidates.Where(candidate => candidate.IsSelected).ToArray();
            selectedCount = selected.Length;
            if (selected.Length == 0)
            {
                AppendSessionMessage("No candidates selected for recovery.");
                AppendCandidateActivity("Recovery skipped: no candidates selected.");
                return;
            }

            if (_selectedSource is null)
            {
                AppendSessionMessage("Recovery blocked: source is not selected.");
                AppendCandidateActivity("Recovery blocked: no source selected.");
                return;
            }

            var sourcePath = ResolveProbePath(_selectedSource);
            if (string.IsNullOrWhiteSpace(sourcePath))
            {
                AppendSessionMessage("Recovery blocked: source path is unavailable.");
                AppendCandidateActivity("Recovery blocked: source path unavailable.");
                return;
            }

            if (string.IsNullOrWhiteSpace(DestinationPathTextBox.Text))
            {
                AppendSessionMessage("Recovery blocked: destination path is missing.");
                AppendCandidateActivity("Recovery blocked: destination path missing.");
                return;
            }

            var destination = Path.GetFullPath(DestinationPathTextBox.Text);
            if (!Directory.Exists(destination))
            {
                AppendSessionMessage("Recovery blocked: destination folder does not exist.");
                AppendCandidateActivity("Recovery blocked: destination folder does not exist.");
                return;
            }

            recoveryRoot = Path.Combine(destination, "RecoveredFiles");
            Directory.CreateDirectory(recoveryRoot);

            if (_activeSessionId.HasValue)
            {
                await _sessionStore.UpdateStatusAsync(
                    _activeSessionId.Value,
                    "recovering",
                    $"Recovering {selected.Length} selected candidates.",
                    operationToken);
            }

            foreach (var candidate in selected)
            {
                operationToken.ThrowIfCancellationRequested();

                if (candidate.Directory)
                {
                    candidate.CandidateStatus = RecoveryCandidateStatus.Invalid;
                    candidate.LastRecoveryStatusCode = -410;
                    candidate.LastRecoveryDiagnosticsFlags = null;
                    candidate.LastRecoveredBytes = 0;
                    candidate.LastRecoveryPartial = null;
                    candidate.RecoveryDiagnostics = "Directory record recovery is not implemented.";
                    failed++;
                    AppendSessionMessage($"Skipped directory candidate R{candidate.RecordNumber}: directory recovery is not yet implemented.");
                    await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                    continue;
                }

                if (candidate.IsGhostRecord)
                {
                    candidate.CandidateStatus = RecoveryCandidateStatus.Invalid;
                    candidate.LastRecoveryStatusCode = -411;
                    candidate.LastRecoveryDiagnosticsFlags = null;
                    candidate.LastRecoveredBytes = 0;
                    candidate.LastRecoveryPartial = null;
                    candidate.RecoveryDiagnostics = "Ghost candidate inferred from journal evidence and lacks recoverable MFT data.";
                    failed++;
                    AppendSessionMessage($"Skipped ghost candidate R{candidate.RecordNumber}: no recoverable MFT-backed stream metadata.");
                    await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                    continue;
                }

                var relativePath = BuildRecoveryRelativePath(candidate);
                var targetPath = Path.Combine(recoveryRoot, relativePath);
                var targetDirectory = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrWhiteSpace(targetDirectory))
                {
                    Directory.CreateDirectory(targetDirectory);
                }

                var result = NativeEngineProbe.RecoverNtfsCandidateToFile(
                    sourcePath,
                    _selectedSource.Kind,
                    candidate.RecordNumber,
                    targetPath);

                if (result.Success)
                {
                    if (result.Partial)
                    {
                        candidate.CandidateStatus = RecoveryCandidateStatus.Partial;
                        partial++;
                    }
                    else
                    {
                        candidate.CandidateStatus = RecoveryCandidateStatus.Full;
                        recovered++;
                    }

                    candidate.LastRecoveryStatusCode = result.StatusCode;
                    candidate.LastRecoveryDiagnosticsFlags = result.DiagnosticsFlags;
                    candidate.LastRecoveredBytes = result.BytesWritten;
                    candidate.LastRecoveryPartial = result.Partial;
                    candidate.RecoveryDiagnostics = result.DiagnosticsSummary;
                    candidate.IsSelected = false;
                    AppendSessionMessage(
                        $"Recovered R{candidate.RecordNumber} to {targetPath} ({(result.Partial ? "partial" : "full")}, {result.BytesWritten} bytes). Diagnostics: {result.DiagnosticsSummary}");
                }
                else
                {
                    candidate.CandidateStatus = MapRecoveryFailureStatus(result.StatusCode);
                    candidate.LastRecoveryStatusCode = result.StatusCode;
                    candidate.LastRecoveryDiagnosticsFlags = result.DiagnosticsFlags;
                    candidate.LastRecoveredBytes = result.BytesWritten;
                    candidate.LastRecoveryPartial = null;
                    candidate.RecoveryDiagnostics = result.DiagnosticsSummary;
                    if (candidate.CandidateStatus == RecoveryCandidateStatus.OverwrittenRisk)
                    {
                        overwrittenRisk++;
                    }
                    failed++;
                    AppendSessionMessage(
                        $"Recovery failed for R{candidate.RecordNumber}: {result.Message} (status {result.StatusCode}). Diagnostics: {result.DiagnosticsSummary}");
                }

                await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
            }

            RefreshCandidateView();
            StatusTextBlock.Text = "Recovery execution completed";

            if (_activeSessionId.HasValue)
            {
                await _sessionLogWriter.LogEventAsync(_activeSessionId.Value, "candidate_recovery", new
                {
                    selected_count = selected.Length,
                    recovered_full = recovered,
                    recovered_partial = partial,
                    failed,
                    overwritten_risk = overwrittenRisk,
                    destination_root = recoveryRoot,
                }, operationToken);

                await _sessionStore.UpdateStatusAsync(
                    _activeSessionId.Value,
                    "ready",
                    $"Recovery completed: full={recovered}, partial={partial}, failed={failed}, overwritten-risk={overwrittenRisk}.",
                    operationToken);

                try
                {
                    var reportPath = await WriteRecoveryReportAsync(
                        _activeSessionId.Value,
                        selected,
                        recovered,
                        partial,
                        failed,
                        overwrittenRisk,
                        recoveryRoot,
                        operationToken);

                    await _sessionLogWriter.LogEventAsync(_activeSessionId.Value, "candidate_recovery_report", new
                    {
                        report_path = reportPath,
                        selected_count = selected.Length,
                        recovered_full = recovered,
                        recovered_partial = partial,
                        failed,
                        overwritten_risk = overwrittenRisk,
                    }, operationToken);

                    AppendSessionMessage($"Recovery report written: {reportPath}");
                }
                catch (Exception ex)
                {
                    AppendSessionMessage($"Recovery report generation warning: {ex.Message}");
                }
            }

            AppendSessionMessage($"Recovery summary: full={recovered}, partial={partial}, failed={failed}, overwritten-risk={overwrittenRisk}.");
            AppendCandidateActivity($"Recovery summary full={recovered}, partial={partial}, failed={failed}, overwritten-risk={overwrittenRisk}.");
        }
        catch (OperationCanceledException)
        {
            RefreshCandidateView();
            AppendSessionMessage("Recovery execution canceled.");
            AppendCandidateActivity("Recovery canceled.");
            StatusTextBlock.Text = "Recovery execution canceled";

            if (_activeSessionId.HasValue)
            {
                await TryMarkSessionCanceledAsync(
                    _activeSessionId.Value,
                    $"Recovery canceled after progress full={recovered}, partial={partial}, failed={failed}, overwritten-risk={overwrittenRisk}, selected={selectedCount}.");
            }
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Recovery execution failed: {ex.Message}");
            AppendCandidateActivity("Recovery execution failed.");
            StatusTextBlock.Text = "Recovery execution failed";

            if (_activeSessionId.HasValue)
            {
                await TryMarkSessionFailedAsync(_activeSessionId.Value, "recovery-error", ex.Message, null);
            }
        }
        finally
        {
            CompleteOperationScope(operationScope);
        }
    }

    private async Task<string> WriteRecoveryReportAsync(
        Guid sessionId,
        IReadOnlyList<QuickScanCandidateRow> selected,
        int recovered,
        int partial,
        int failed,
        int overwrittenRisk,
        string recoveryRoot,
        CancellationToken cancellationToken)
    {
        var markdown = BuildRecoveryReportMarkdown(
            sessionId,
            selected,
            recovered,
            partial,
            failed,
            overwrittenRisk,
            recoveryRoot);

        return await _sessionLogWriter.WriteRecoveryReportAsync(sessionId, markdown, cancellationToken);
    }

    private string BuildRecoveryReportMarkdown(
        Guid sessionId,
        IReadOnlyList<QuickScanCandidateRow> selected,
        int recovered,
        int partial,
        int failed,
        int overwrittenRisk,
        string recoveryRoot)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Recovery Session Report");
        builder.AppendLine();
        builder.AppendLine($"- Session ID: `{sessionId:D}`");
        builder.AppendLine($"- Generated UTC: `{DateTimeOffset.UtcNow:O}`");
        builder.AppendLine($"- Source: `{_selectedSource?.DisplayName ?? "(unknown)"}`");
        builder.AppendLine($"- Destination Root: `{recoveryRoot}`");
        builder.AppendLine($"- Selected Candidates: `{selected.Count}`");
        builder.AppendLine($"- Recovered Full: `{recovered}`");
        builder.AppendLine($"- Recovered Partial: `{partial}`");
        builder.AppendLine($"- Failed: `{failed}`");
        builder.AppendLine($"- Overwritten Risk: `{overwrittenRisk}`");
        builder.AppendLine();
        builder.AppendLine("## Candidate Details");
        builder.AppendLine();
        builder.AppendLine("| Record | Name | Original Path | Data Size | Modified UTC | Attr | Status | Recover Code | Diag Flags | Recovered Bytes | Partial | Diagnostics |");
        builder.AppendLine("|---|---|---|---:|---|---|---|---:|---:|---:|---|---|");

        foreach (var candidate in selected)
        {
            var diagnosticsFlags = candidate.LastRecoveryDiagnosticsFlags.HasValue
                ? $"0x{candidate.LastRecoveryDiagnosticsFlags.Value:X8}"
                : "-";
            var recoveredBytes = candidate.LastRecoveredBytes.HasValue
                ? candidate.LastRecoveredBytes.Value.ToString(CultureInfo.InvariantCulture)
                : "-";
            var partialValue = candidate.LastRecoveryPartial.HasValue
                ? (candidate.LastRecoveryPartial.Value ? "yes" : "no")
                : "-";
            var recoverCode = candidate.LastRecoveryStatusCode.HasValue
                ? candidate.LastRecoveryStatusCode.Value.ToString(CultureInfo.InvariantCulture)
                : "-";
            var dataSize = candidate.DataSizeBytes.HasValue
                ? candidate.DataSizeBytes.Value.ToString(CultureInfo.InvariantCulture)
                : "-";
            var modifiedUtc = EscapeMarkdownCell(candidate.ModifiedUtcDisplay);
            var fileAttributes = EscapeMarkdownCell(candidate.FileAttributesDisplay);

            builder.AppendLine(
                $"| {candidate.RecordNumber} | {EscapeMarkdownCell(candidate.Name)} | {EscapeMarkdownCell(candidate.OriginalPath)} | {dataSize} | {modifiedUtc} | {fileAttributes} | {EscapeMarkdownCell(candidate.CandidateStatus.ToStorageCode())} | {recoverCode} | {diagnosticsFlags} | {recoveredBytes} | {partialValue} | {EscapeMarkdownCell(candidate.RecoveryDiagnostics)} |");
        }

        return builder.ToString();
    }

    private static string BuildSelectedCandidatesCsv(IReadOnlyList<QuickScanCandidateRow> selected)
    {
        var lines = new List<string>
        {
            "record_number,deleted,is_ghost_record,directory,non_resident_data,has_named_data_streams,compressed,sparse,encrypted,name,original_path,parent_record,data_size_bytes,allocated_size_bytes,file_attributes,created_filetime_utc,modified_filetime_utc,mft_modified_filetime_utc,accessed_filetime_utc,evidence_source,confidence_tier,status,recovery_status_code,recovery_diagnostics_flags,recovered_bytes,recovery_partial,recovery_diagnostics"
        };

        foreach (var candidate in selected)
        {
            lines.Add(string.Join(",",
                candidate.RecordNumber.ToString(CultureInfo.InvariantCulture),
                candidate.Deleted ? "1" : "0",
                candidate.IsGhostRecord ? "1" : "0",
                candidate.Directory ? "1" : "0",
                candidate.NonResidentData ? "1" : "0",
                candidate.HasNamedDataStreams ? "1" : "0",
                candidate.IsCompressed ? "1" : "0",
                candidate.IsSparse ? "1" : "0",
                candidate.IsEncrypted ? "1" : "0",
                EscapeCsv(candidate.Name),
                EscapeCsv(candidate.OriginalPath),
                EscapeCsv(candidate.ParentRecord),
                EscapeCsv(candidate.DataSizeBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.AllocatedSizeBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.FileAttributesDisplay),
                EscapeCsv(candidate.CreatedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.ModifiedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.MftModifiedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.AccessedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.EvidenceSource),
                EscapeCsv(candidate.ConfidenceTier),
                EscapeCsv(candidate.CandidateStatus.ToStorageCode()),
                EscapeCsv(candidate.LastRecoveryStatusCode?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.LastRecoveryDiagnosticsFlags?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.LastRecoveredBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.LastRecoveryPartial.HasValue ? (candidate.LastRecoveryPartial.Value ? "1" : "0") : null),
                EscapeCsv(candidate.RecoveryDiagnostics)));
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static string EscapeMarkdownCell(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "-";
        }

        return value
            .Replace("|", "\\|", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", "<br/>", StringComparison.Ordinal);
    }

    private static string EscapeCsv(string? value)
    {
        var safe = value ?? string.Empty;
        var requiresQuotes = safe.Contains(',') || safe.Contains('"') || safe.Contains('\n') || safe.Contains('\r');
        if (!requiresQuotes)
        {
            return safe;
        }

        return "\"" + safe.Replace("\"", "\"\"") + "\"";
    }

    private static string BuildRecoveryRelativePath(QuickScanCandidateRow candidate)
    {
        var raw = candidate.OriginalPath;
        if (string.IsNullOrWhiteSpace(raw) || raw == "(unresolved)")
        {
            raw = string.IsNullOrWhiteSpace(candidate.Name) || candidate.Name == "(unknown)"
                ? $"record-{candidate.RecordNumber}.bin"
                : candidate.Name;
        }

        var parts = raw
            .Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(SanitizePathSegment)
            .Where(part => !string.IsNullOrWhiteSpace(part))
            .ToArray();

        if (parts.Length == 0)
        {
            return $"record-{candidate.RecordNumber}.bin";
        }

        var combined = Path.Combine(parts);
        if (combined.EndsWith(Path.DirectorySeparatorChar))
        {
            return Path.Combine(combined, $"record-{candidate.RecordNumber}.bin");
        }

        return combined;
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

    private CancellationTokenSource StartNewOperationScope()
    {
        _operationCts?.Cancel();
        _operationCts?.Dispose();
        _operationCts = new CancellationTokenSource();
        return _operationCts;
    }

    private void CompleteOperationScope(CancellationTokenSource operationScope)
    {
        if (!ReferenceEquals(_operationCts, operationScope))
        {
            return;
        }

        _operationCts.Dispose();
        _operationCts = null;
    }

    private async Task PersistCandidateRecoveryDiagnosticsAsync(
        QuickScanCandidateRow candidate,
        CancellationToken cancellationToken)
    {
        if (!_activeSessionId.HasValue)
        {
            return;
        }

        await _sessionStore.UpdateQuickScanCandidateRecoveryAsync(
            _activeSessionId.Value,
            candidate.Ordinal,
            candidate.CandidateStatus,
            candidate.LastRecoveryStatusCode,
            candidate.LastRecoveryDiagnosticsFlags,
            candidate.LastRecoveredBytes,
            candidate.LastRecoveryPartial,
            string.IsNullOrWhiteSpace(candidate.RecoveryDiagnostics) ? null : candidate.RecoveryDiagnostics,
            DateTimeOffset.UtcNow,
            cancellationToken);
    }

    private async Task TryMarkSessionCanceledAsync(Guid sessionId, string message)
    {
        try
        {
            await _sessionStore.UpdateStatusAsync(sessionId, "canceled", message, CancellationToken.None);
            await _sessionLogWriter.LogEventAsync(sessionId, "operation_canceled", new
            {
                message,
            }, CancellationToken.None);
            await _sessionLogWriter.LogMessageAsync(sessionId, message, CancellationToken.None);
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Session cancellation logging warning: {ex.Message}");
        }
    }

    private async Task TryMarkSessionFailedAsync(Guid sessionId, string status, string message, int? statusCode)
    {
        try
        {
            await _sessionStore.UpdateStatusAsync(sessionId, status, message, CancellationToken.None);
            await _sessionLogWriter.LogEventAsync(sessionId, "operation_error", new
            {
                status,
                message,
                status_code = statusCode,
            }, CancellationToken.None);
            await _sessionLogWriter.LogMessageAsync(sessionId, $"Operation error ({status}): {message}", CancellationToken.None);
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Session failure logging warning: {ex.Message}");
        }
    }

    private void AppendSessionMessage(string message)
    {
        SessionOutputTextBox.AppendText($"[{DateTimeOffset.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        SessionOutputTextBox.ScrollToEnd();
    }

    private void SessionOutputTextBox_PreviewMouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (sender is not System.Windows.Controls.TextBox textBox)
        {
            return;
        }

        var scrollViewer = FindDescendantScrollViewer(textBox);
        if (scrollViewer is null)
        {
            return;
        }

        if (e.Delta < 0)
        {
            if (scrollViewer.VerticalOffset < scrollViewer.ScrollableHeight)
            {
                scrollViewer.LineDown();
                e.Handled = true;
            }

            return;
        }

        if (e.Delta > 0 && scrollViewer.VerticalOffset > 0)
        {
            scrollViewer.LineUp();
            e.Handled = true;
        }
    }

    private static System.Windows.Controls.ScrollViewer? FindDescendantScrollViewer(System.Windows.DependencyObject parent)
    {
        if (parent is System.Windows.Controls.ScrollViewer directScrollViewer)
        {
            return directScrollViewer;
        }

        var children = System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent);
        for (var index = 0; index < children; index++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, index);
            var found = FindDescendantScrollViewer(child);
            if (found is not null)
            {
                return found;
            }
        }

        return null;
    }

    private async Task RunPreviewReadAsync(SourceCandidate source, Guid sessionId)
    {
        _previewReadCts?.Cancel();
        _previewReadCts?.Dispose();
        _previewReadCts = new CancellationTokenSource();

        AppendSessionMessage("Starting preview read (8 MiB cap, 1 MiB chunks).");

        var progress = new Progress<ReadPreviewProgress>(state =>
        {
            StatusTextBlock.Text =
                $"Preview read {state.BytesRead}/{state.TargetBytes} bytes at {state.ThroughputMiBPerSec:0.00} MiB/s";
        });

        ReadPreviewResult result;
        try
        {
            result = await _previewScanner.RunAsync(
                source,
                maxBytes: 8UL * 1024 * 1024,
                chunkSize: 1024 * 1024,
                cancellationToken: _previewReadCts.Token,
                progress: progress);
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Preview read error: {ex.Message}");
            StatusTextBlock.Text = "Preview read failed";
            await _sessionLogWriter.LogEventAsync(sessionId, "preview_read", new
            {
                succeeded = false,
                canceled = false,
                bytes_read = 0UL,
                chunks_read = 0,
                status_code = -500,
                message = ex.Message,
            }, CancellationToken.None);
            return;
        }

        await _sessionLogWriter.LogEventAsync(sessionId, "preview_read", new
        {
            succeeded = result.Succeeded,
            canceled = result.Canceled,
            bytes_read = result.BytesRead,
            chunks_read = result.ChunksRead,
            status_code = result.StatusCode,
            message = result.Message,
        }, CancellationToken.None);

        AppendSessionMessage(
            $"Preview read result: {result.Message} (bytes {result.BytesRead}, chunks {result.ChunksRead}, status {result.StatusCode}).");

        if (result.Canceled)
        {
            StatusTextBlock.Text = "Preview read canceled";
            return;
        }

        StatusTextBlock.Text = result.Succeeded ? "Preview read completed" : "Preview read failed";
    }

    private void CancelPreviewButton_Click(object sender, RoutedEventArgs e)
    {
        var canceledAny = false;

        if (_previewReadCts is null)
        {
            // no-op
        }
        else
        {
            _previewReadCts.Cancel();
            canceledAny = true;
            AppendSessionMessage("Preview read cancellation requested.");
        }

        if (_refreshCts is not null)
        {
            _refreshCts.Cancel();
            canceledAny = true;
            AppendSessionMessage("Source enumeration cancellation requested.");
        }

        if (_operationCts is not null)
        {
            _operationCts.Cancel();
            canceledAny = true;
            AppendSessionMessage("Active operation cancellation requested.");
        }

        if (!canceledAny)
        {
            AppendSessionMessage("No cancellable operation is currently running.");
        }
    }

    private void RestartElevatedButton_Click(object sender, RoutedEventArgs e)
    {
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath))
        {
            AppendSessionMessage("Elevation restart failed: executable path unavailable.");
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = processPath,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory,
            });

            AppendSessionMessage("Elevation restart launched. Closing current process.");
            System.Windows.Application.Current.Shutdown();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            AppendSessionMessage("Elevation request canceled by user.");
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Elevation restart failed: {ex.Message}");
        }
    }

    private void RefreshElevationState()
    {
        _isElevated = _privilegeService.IsElevated();
        ElevationWarningBorder.Visibility = _isElevated ? Visibility.Collapsed : Visibility.Visible;

        if (_isElevated || _elevationWarningLogged)
        {
            return;
        }

        const string warningMessage = "App is not elevated. Raw device opens can fail for some sources.";
        _validationOutput.Add($"Warning: {warningMessage}");
        AppendSessionMessage($"Safety warning: {warningMessage}");
        _elevationWarningLogged = true;
    }

    private static string? ResolveProbePath(SourceCandidate source)
    {
        return source.Kind switch
        {
            RecoverySourceKind.ImageFile => source.SourcePath,
            RecoverySourceKind.Volume => source.DevicePath,
            RecoverySourceKind.Partition => source.DevicePath,
            RecoverySourceKind.PhysicalDisk => source.DevicePath,
            _ => null,
        };
    }

    private static int GetAlignedBufferLength(uint alignmentBytes, int preferredSize)
    {
        if (alignmentBytes == 0)
        {
            return preferredSize;
        }

        var alignment = (int)Math.Min(alignmentBytes, int.MaxValue);
        var remainder = preferredSize % alignment;
        if (remainder == 0)
        {
            return preferredSize;
        }

        return checked(preferredSize + (alignment - remainder));
    }
}

