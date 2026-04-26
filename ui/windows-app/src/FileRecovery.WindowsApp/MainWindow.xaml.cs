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
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media.Imaging;
using System.Xml.Linq;
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
        public string Name { get; set; } = string.Empty;
        public string OriginalPath { get; set; } = string.Empty;
        public string RecoveredPath { get; set; } = string.Empty;
        public string FileType { get; init; } = "unknown";
        public string ParentRecord { get; init; } = string.Empty;
        public string ClusterId { get; init; } = string.Empty;
        public int ClusterSize { get; init; }
        public int DeduplicatedCount { get; init; }
        public string ClusterDisplay => string.IsNullOrWhiteSpace(ClusterId)
            ? string.Empty
            : $"{ClusterId} ({ClusterSize.ToString(CultureInfo.InvariantCulture)})";
        public string DedupDisplay => DeduplicatedCount > 0
            ? DeduplicatedCount.ToString(CultureInfo.InvariantCulture)
            : string.Empty;
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
        public ulong? CarveOffsetBytes { get; init; }
        public ulong? CarveLengthBytes { get; init; }
        public string CarveFormat { get; init; } = string.Empty;
        public string CarveOffsetDisplay => CarveOffsetBytes.HasValue
            ? $"0x{CarveOffsetBytes.Value:X}"
            : string.Empty;
        public string EvidenceSource { get; init; } = "MFT";
        public string ConfidenceTier { get; init; } = "Medium";
        public int ConfidenceScore => ComputeConfidenceScore(ConfidenceTier, ConfidenceReason);
        public string ConfidenceScoreDisplay => ConfidenceScore.ToString(CultureInfo.InvariantCulture);
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

        private static int ComputeConfidenceScore(string tier, string reason)
        {
            var reasonMatch = Regex.Match(
                reason ?? string.Empty,
                "(?i)\\bscore\\s*(?<score>\\d{1,3})\\b",
                RegexOptions.CultureInvariant);
            if (reasonMatch.Success
                && int.TryParse(reasonMatch.Groups["score"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            {
                return Math.Clamp(parsed, 0, 100);
            }

            return tier.Trim().ToLowerInvariant() switch
            {
                "very high" => 92,
                "high" => 78,
                "medium" => 60,
                "low" => 38,
                "very low" => 20,
                _ => 50,
            };
        }
    }

    private sealed record DirectoryRecoverySelection(
        QuickScanCandidateRow Directory,
        IReadOnlyList<QuickScanCandidateRow> Children);

    private sealed record EncryptedUnlockRequest(
        string Provider,
        string CredentialKind,
        string CredentialMaterial);

    private readonly IDeviceEnumerationService _deviceEnumerationService;
    private readonly SourceDestinationSafetyValidator _safetyValidator;
    private readonly IPrivilegeService _privilegeService;
    private readonly IImageAcquisitionService _imageAcquisitionService;
    private readonly IWinPeRuntimeService _winPeRuntimeService;
    private readonly IStorageHealthTelemetryService _storageHealthTelemetryService;
    private readonly SqliteSessionStore _sessionStore;
    private readonly SessionLogWriter _sessionLogWriter;
    private readonly ReadPreviewScanner _previewScanner;
    private readonly CandidatePostProcessor _candidatePostProcessor;
    private readonly ObservableCollection<SourceCandidate> _sources = [];
    private readonly ObservableCollection<string> _validationOutput = [];
    private readonly ObservableCollection<string> _smartHealthOutput = [];
    private readonly ObservableCollection<QuickScanCandidateRow> _quickScanCandidates = [];
    private readonly ObservableCollection<string> _candidateActivity = [];
    private static readonly TimeSpan SessionRetentionAge = TimeSpan.FromDays(30);
    private const string UiBuildTag = "phase17-streaming-signatures-20260420-1245";
    private const int MaxUiActivityLogEntries = 400;
    private const int SessionRetentionMaxCount = 50;
    private const ulong FullScanCarveChunkBytes = 64UL * 1024UL * 1024UL;
    private const ulong FullScanCarveOverlapBytes = 1UL * 1024UL * 1024UL;
    private static readonly Regex PdfTitleRegex = new("/Title\\s*\\((?<title>[^\\)]{3,120})\\)", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private const int DefaultQuickScanMaxRecords = 2048;
    private const int DefaultCandidateCapacity = 1024;
    private const int DefaultPreviewCapMiB = 8;
    private const int DefaultPreviewChunkKiB = 1024;
    private const int DefaultNetworkChunkKiB = 512;
    private SourceCandidate? _selectedSource;
    private ICollectionView? _quickScanCandidatesView;
    private CancellationTokenSource? _previewReadCts;
    private CancellationTokenSource? _refreshCts;
    private CancellationTokenSource? _operationCts;
    private Guid? _activeSessionId;
    private string _activeSessionSourceClass = SessionSourceClass.Local;
    private string? _activeSignaturePackSet;
    private string? _activeCustodyHashChainRef;
    private RemoteExecutionStatus _lastRemoteExecutionStatus = RemoteExecutionStatus.NotRequested;
    private RemoteExecutionErrorCode _lastRemoteExecutionErrorCode = RemoteExecutionErrorCode.None;
    private string? _lastRemoteExecutionMessage;
    private string? _lastRemoteExecutionIntegrityHash;
    private bool _isElevated;
    private bool _elevationWarningLogged;
    private bool _filterDeletedOnly;
    private bool _filterRecoverableOnly;
    private bool _filterSelectedOnly;
    private string _candidateSearchTerm = string.Empty;
    private string _filterFileType = "All";
    private string _filterStatus = "All";
    private string _filterEvidence = "All";
    private string _filterConfidence = "All";
    private ulong? _filterMinSizeBytes;
    private ulong? _filterMaxSizeBytes;
    private DateTime? _filterModifiedFromUtc;
    private DateTime? _filterModifiedToUtc;
    private DateTime? _filterDeletedFromUtc;
    private DateTime? _filterDeletedToUtc;
    private int _candidateClusterCount;
    private int _candidateDedupedCount;
    private bool _winPeReadinessWarningLogged;
    private RuntimeEnvironmentProfile _runtimeEnvironmentProfile =
        new(
            Mode: RuntimeEnvironmentMode.StandardWindows,
            BootDrive: "C:",
            MiniNtRegistryDetected: false,
            WinPeOverrideDetected: false,
            BootDriveLooksLikeWinPe: false);

    public MainWindow()
    {
        InitializeComponent();

        var topology = new WindowsStorageTopologyService();
        _deviceEnumerationService = new WindowsDeviceEnumerationService(topology);
        _safetyValidator = new SourceDestinationSafetyValidator(topology);
        _privilegeService = new WindowsPrivilegeService();
        _imageAcquisitionService = new FileImageAcquisitionService();
        _winPeRuntimeService = new WinPeRuntimeService(new WindowsWinPeRuntimeProbe());
        _storageHealthTelemetryService = new WindowsStorageHealthTelemetryService();
        _sessionStore = new SqliteSessionStore();
        _sessionLogWriter = new SessionLogWriter();
        _previewScanner = new ReadPreviewScanner();
        _candidatePostProcessor = new CandidatePostProcessor();

        SourcesDataGrid.ItemsSource = _sources;
        ValidationListBox.ItemsSource = _validationOutput;
        SmartHealthListBox.ItemsSource = _smartHealthOutput;
        CandidateActivityListBox.ItemsSource = _candidateActivity;

        _quickScanCandidates.CollectionChanged += (_, _) => UpdateCandidateSummary();
        _quickScanCandidatesView = CollectionViewSource.GetDefaultView(_quickScanCandidates);
        _quickScanCandidatesView.Filter = FilterQuickScanCandidate;
        QuickScanCandidatesDataGrid.ItemsSource = _quickScanCandidatesView;
        InitializeCandidateFilterControls();
        InitializeSafetyWarningsPage();
        ClearPreviewPanel();
        OperationProgressBar.Value = 0;
        ThroughputStatusTextBlock.Text = "Throughput: -";

        ScanModeComboBox.ItemsSource = Enum.GetValues<ScanMode>();
        ScanModeComboBox.SelectedItem = ScanMode.Quick;
        NetworkProtocolComboBox.ItemsSource = Enum.GetValues<NetworkSourceProtocol>();
        NetworkProtocolComboBox.SelectedItem = NetworkSourceProtocol.Smb;
        RemoteAgentModeComboBox.ItemsSource = Enum.GetValues<RemoteAgentMode>();
        RemoteAgentModeComboBox.SelectedItem = RemoteAgentMode.Disabled;
        ConstrainedNetworkChunkKiBTextBox.Text = DefaultNetworkChunkKiB.ToString(CultureInfo.InvariantCulture);
        _runtimeEnvironmentProfile = _winPeRuntimeService.GetRuntimeProfile();
        ApplyRuntimeModeUi();
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
            await RefreshSmartHealthTelemetryAsync(CancellationToken.None);
            await LoadLatestPersistedCandidatesAsync(CancellationToken.None);
            AppendSessionMessage($"UI build: {UiBuildTag}");
            AppendSessionMessage($"Session DB: {_sessionStore.DatabasePath}");
            AppendSessionMessage(
                $"Runtime mode: {_runtimeEnvironmentProfile.Mode} (boot-drive={_runtimeEnvironmentProfile.BootDrive}, MiniNT={_runtimeEnvironmentProfile.MiniNtRegistryDetected}, override={_runtimeEnvironmentProfile.WinPeOverrideDetected}).");
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

            AppendVssSnapshotSources();
            AppendOfflineReadinessDiagnostics(result.Sources);
            await RefreshSmartHealthTelemetryAsync(cancellationToken);
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

    private void AppendVssSnapshotSources()
    {
        if (_runtimeEnvironmentProfile.IsWinPe)
        {
            AppendSessionMessage("VSS snapshot enumeration skipped in WinPE offline mode.");
            return;
        }

        var vss = NativeEngineProbe.ListVssSnapshots(snapshotCapacity: 64);
        if (!vss.EngineAvailable)
        {
            return;
        }

        if (!vss.Success)
        {
            AppendSessionMessage(
                $"VSS snapshot enumeration skipped: {vss.Message} (status {vss.StatusCode}).");
            return;
        }

        if (vss.Snapshots.Count == 0)
        {
            return;
        }

        var existingIds = new HashSet<string>(
            _sources.Select(source => source.Id),
            StringComparer.OrdinalIgnoreCase);
        var added = 0;
        foreach (var snapshot in vss.Snapshots)
        {
            var sourceId = $"vss:{snapshot.SnapshotId}";
            if (!existingIds.Add(sourceId))
            {
                continue;
            }

            var timestampDisplay = FormatSnapshotTimestamp(snapshot.InstallTimeUtc);

            _sources.Add(new SourceCandidate(
                Id: sourceId,
                Kind: RecoverySourceKind.Volume,
                DisplayName: $"VSS Snapshot {timestampDisplay}",
                DevicePath: snapshot.DeviceObject,
                FileSystem: "NTFS (VSS)",
                SizeBytes: null,
                SectorSizeBytes: null,
                DiskIndex: null,
                VolumeIdentity: snapshot.VolumeName,
                SourcePath: snapshot.SnapshotPath,
                ReadOnlyEnforced: true,
                VolumeLabel: snapshot.VolumeName,
                MountedPaths: snapshot.SnapshotPath,
                PartitionInfo: $"Snapshot {snapshot.SnapshotId} ({timestampDisplay})"));
            added++;
        }

        if (added > 0)
        {
            AppendSessionMessage($"VSS snapshots discovered: {added} source(s) added.");
        }
    }

    private void ApplyRuntimeModeUi()
    {
        if (_runtimeEnvironmentProfile.IsWinPe)
        {
            RuntimeModeTextBlock.Text = "Mode: WinPE Offline";
            RuntimeModeTextBlock.Foreground = System.Windows.Media.Brushes.DarkOrange;
            ElevationWarningBorder.Visibility = Visibility.Collapsed;
            RestartElevatedButton.IsEnabled = false;
            RestartElevatedButton.Visibility = Visibility.Collapsed;
            ImportImageButton.IsEnabled = true;
            AddNetworkImageButton.IsEnabled = false;
            NetworkProtocolComboBox.IsEnabled = false;
            NetworkSourcePathTextBox.IsEnabled = false;
            NetworkEndpointHintTextBox.IsEnabled = false;
            ResumeLatestSessionButton.IsEnabled = false;
            SessionMaintenanceButton.IsEnabled = false;
            RemoteAgentModeComboBox.IsEnabled = false;
            RemoteAgentEndpointTextBox.IsEnabled = false;
            RaidMemberSourcesTextBox.IsEnabled = false;
            AppendSessionMessage("WinPE mode active: network source intake disabled; using offline scan/recovery flow.");
            return;
        }

        RuntimeModeTextBlock.Text = "Mode: Standard Windows";
        RuntimeModeTextBlock.Foreground = System.Windows.Media.Brushes.Teal;
        RestartElevatedButton.IsEnabled = true;
        RestartElevatedButton.Visibility = Visibility.Visible;
        AddNetworkImageButton.IsEnabled = true;
        NetworkProtocolComboBox.IsEnabled = true;
        NetworkSourcePathTextBox.IsEnabled = true;
        NetworkEndpointHintTextBox.IsEnabled = true;
        ResumeLatestSessionButton.IsEnabled = true;
        SessionMaintenanceButton.IsEnabled = true;
        RemoteAgentModeComboBox.IsEnabled = true;
        RemoteAgentEndpointTextBox.IsEnabled = true;
        RaidMemberSourcesTextBox.IsEnabled = true;
    }

    private bool TryValidateWinPeOfflineReadiness(
        IEnumerable<SourceCandidate> sources,
        bool verbose)
    {
        if (!_runtimeEnvironmentProfile.IsWinPe)
        {
            return true;
        }

        var readiness = _winPeRuntimeService.BuildOfflineStorageReadiness(
            sources,
            DestinationPathTextBox.Text);
        if (readiness.IsReady)
        {
            if (verbose)
            {
                AppendSessionMessage(
                    $"WinPE offline readiness OK (sources={readiness.VisibleSourceCount}, destinations={readiness.VisibleDestinationVolumeCount}).");
            }

            _winPeReadinessWarningLogged = false;
            return true;
        }

        foreach (var issue in readiness.Issues)
        {
            _validationOutput.Add($"Error: {issue}");
            if (verbose || !_winPeReadinessWarningLogged)
            {
                AppendSessionMessage($"WinPE readiness issue: {issue}");
            }
        }

        foreach (var warning in readiness.Warnings)
        {
            _validationOutput.Add($"Warning: {warning}");
            if (verbose || !_winPeReadinessWarningLogged)
            {
                AppendSessionMessage($"WinPE readiness warning: {warning}");
            }
        }

        _winPeReadinessWarningLogged = true;
        return false;
    }

    private void AppendOfflineReadinessDiagnostics(IEnumerable<SourceCandidate> sources)
    {
        _ = TryValidateWinPeOfflineReadiness(sources, verbose: true);
    }

    private static string FormatSnapshotTimestamp(string? installTimeUtc)
    {
        if (string.IsNullOrWhiteSpace(installTimeUtc))
        {
            return "unknown timestamp";
        }

        if (DateTimeOffset.TryParse(installTimeUtc, out var parsed))
        {
            return parsed.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
        }

        return installTimeUtc;
    }

    private static string BuildImageAcquisitionDefaultName(SourceCandidate source)
    {
        var timestamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var imageBaseName = !string.IsNullOrWhiteSpace(source.SourcePath)
            ? Path.GetFileNameWithoutExtension(source.SourcePath)
            : "clone";
        return source.Kind switch
        {
            RecoverySourceKind.PhysicalDisk => $"disk-{source.DiskIndex ?? 0}-{timestamp}.img",
            RecoverySourceKind.Partition => $"partition-{source.DiskIndex ?? 0}-{timestamp}.img",
            RecoverySourceKind.Volume => $"volume-{timestamp}.img",
            RecoverySourceKind.ImageFile => $"{imageBaseName}-{timestamp}.img",
            _ => $"acquired-{timestamp}.img",
        };
    }

    private void SourcesDataGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _selectedSource = SourcesDataGrid.SelectedItem as SourceCandidate;
        if (_selectedSource is not null)
        {
            AppendSessionMessage(
                $"Source inspector: id={_selectedSource.Id}, type={_selectedSource.Kind}, fs={_selectedSource.FileSystem ?? "unknown"}, size={_selectedSource.SizeBytes?.ToString(CultureInfo.InvariantCulture) ?? "unknown"}, path={_selectedSource.SourcePath ?? _selectedSource.DevicePath ?? "n/a"}.");
        }
    }

    private async void ImportImageButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Image Files (*.img;*.dd;*.raw;*.vmdk;*.vhd;*.vhdx;*.qcow2)|*.img;*.dd;*.raw;*.vmdk;*.vhd;*.vhdx;*.qcow2|All Files (*.*)|*.*",
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

    private async void AddNetworkImageButton_Click(object sender, RoutedEventArgs e)
    {
        var sourcePath = (NetworkSourcePathTextBox.Text ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            StatusTextBlock.Text = "Network source path required";
            AppendSessionMessage("Network image import blocked: network source path is empty.");
            return;
        }

        var protocol = NetworkProtocolComboBox.SelectedItem is NetworkSourceProtocol selectedProtocol
            ? selectedProtocol
            : NetworkSourceProtocol.Smb;
        var endpointHint = string.IsNullOrWhiteSpace(NetworkEndpointHintTextBox.Text)
            ? null
            : NetworkEndpointHintTextBox.Text.Trim();

        try
        {
            var networkImage = await _deviceEnumerationService.BuildNetworkImageSourceAsync(
                new NetworkSourceRequest(protocol, sourcePath, endpointHint),
                CancellationToken.None);
            _sources.Insert(0, networkImage);
            SourcesDataGrid.SelectedIndex = 0;
            AppendSessionMessage(
                $"Imported network image source ({networkImage.NetworkProtocol}): {networkImage.SourcePath} endpoint={networkImage.NetworkEndpoint ?? "n/a"}");
            StatusTextBlock.Text = "Network image source imported";
        }
        catch (Exception ex)
        {
            StatusTextBlock.Text = "Network image import failed";
            AppendSessionMessage($"Network image import error: {ex.Message}");
        }
    }

    private async void AcquireImageButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedSource is null)
        {
            StatusTextBlock.Text = "Image acquisition blocked: source not selected";
            AppendSessionMessage("Image acquisition blocked: source not selected.");
            return;
        }

        var sourcePath = ResolveProbePath(_selectedSource);
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            StatusTextBlock.Text = "Image acquisition blocked: source path unavailable";
            AppendSessionMessage("Image acquisition blocked: selected source path is unavailable.");
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Raw Image (*.img)|*.img|DD Image (*.dd)|*.dd|Raw Dump (*.raw)|*.raw|All Files (*.*)|*.*",
            FileName = BuildImageAcquisitionDefaultName(_selectedSource),
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var destinationPath = dialog.FileName;
        if (string.Equals(sourcePath, destinationPath, StringComparison.OrdinalIgnoreCase))
        {
            StatusTextBlock.Text = "Image acquisition blocked: destination matches source";
            AppendSessionMessage("Image acquisition blocked: destination image path must be different from source.");
            return;
        }

        var operationScope = StartNewOperationScope();
        var operationToken = operationScope.Token;
        var progressReporter = new Progress<ImageAcquisitionProgress>(state =>
        {
            OperationProgressBar.Value = state.PercentComplete;
            var throughputMiB = state.ThroughputBytesPerSecond / (1024.0 * 1024.0);
            ThroughputStatusTextBlock.Text = $"Throughput: {throughputMiB:0.00} MiB/s";
            StatusTextBlock.Text =
                $"Imaging source... {state.PercentComplete:0.0}% ({state.BytesWritten:N0}/{state.TotalBytes:N0} bytes)";
        });
        if (!TryGetNetworkAcquisitionSettings(
            out var constrainedNetworkChunkSizeBytes,
            out var maxNetworkThroughputBytesPerSecond,
            out var remoteAgentMode,
            out var remoteAgentEndpoint,
            out var chainOfCustodyLogPath,
            out var settingsError))
        {
            StatusTextBlock.Text = "Image acquisition blocked: invalid network settings";
            AppendSessionMessage($"Image acquisition blocked: {settingsError}");
            CompleteOperationScope(operationScope);
            return;
        }
        var sourceIsNetwork = _selectedSource.IsNetworkSource
            || sourcePath.StartsWith(@"\\", StringComparison.Ordinal);

        try
        {
            OperationProgressBar.Value = 0;
            ThroughputStatusTextBlock.Text = "Throughput: 0.00 MiB/s";
            AppendSessionMessage($"Image acquisition started: {sourcePath} -> {destinationPath}");

            var result = await _imageAcquisitionService.AcquireImageAsync(
                new ImageAcquisitionRequest(
                    SourcePath: sourcePath,
                    DestinationImagePath: destinationPath,
                    ChunkSizeBytes: 4 * 1024 * 1024,
                    AllowResume: true,
                    ReadErrorPolicy: ImageReadErrorPolicy.ContinueWithZeroFill,
                    MaxReadErrorChunks: 1024,
                    SourceIsNetwork: sourceIsNetwork,
                    EnableConstrainedNetworkIo: NetworkConstrainedIoCheckBox.IsChecked == true,
                    ConstrainedNetworkChunkSizeBytes: constrainedNetworkChunkSizeBytes,
                    MaxNetworkThroughputBytesPerSecond: maxNetworkThroughputBytesPerSecond,
                    RemoteAgentMode: remoteAgentMode,
                    RemoteAgentEndpoint: remoteAgentEndpoint,
                    ChainOfCustodyLogPath: chainOfCustodyLogPath),
                progressReporter,
                operationToken);

            var image = await _deviceEnumerationService.BuildImageSourceAsync(result.DestinationImagePath, operationToken);
            _sources.Insert(0, image);
            SourcesDataGrid.SelectedIndex = 0;

            OperationProgressBar.Value = 100;
            StatusTextBlock.Text = "Image acquisition completed";
            AppendSessionMessage(
                $"Image acquisition completed ({result.BytesWritten:N0} bytes, SHA256 {result.SourceSha256Hex[..16]}..., resumed={result.Resumed}, read-errors={result.ReadErrorChunks}, zero-filled={result.ZeroFilledBytes:N0} bytes, policy={result.ReadErrorPolicy}).");
            AppendSessionMessage($"Image acquisition state log: {result.StateLogPath}");
            _lastRemoteExecutionStatus = result.RemoteExecutionStatus;
            _lastRemoteExecutionErrorCode = result.RemoteExecutionErrorCode;
            _lastRemoteExecutionMessage = result.RemoteExecutionMessage;
            _lastRemoteExecutionIntegrityHash = result.RemoteExecutionIntegrityHash;
            if (result.SourceIsNetwork)
            {
                var throughputCap = result.MaxNetworkThroughputBytesPerSecond.HasValue
                    ? $"{result.MaxNetworkThroughputBytesPerSecond.Value} B/s"
                    : "none";
                AppendSessionMessage(
                    $"Network acquisition details: constrained={result.ConstrainedNetworkIo}, cap={throughputCap}, remote-agent={result.RemoteAgentMode}, endpoint={result.RemoteAgentEndpoint ?? "n/a"}, checkpoints={result.NetworkCheckpointCount}.");
                if (result.RemoteAgentMode != RemoteAgentMode.Disabled)
                {
                    AppendSessionMessage(
                        $"Remote execution: status={result.RemoteExecutionStatus}, error={result.RemoteExecutionErrorCode}, message={result.RemoteExecutionMessage ?? "n/a"}, integrity={result.RemoteExecutionIntegrityHash ?? "n/a"}.");
                }
                if (!string.IsNullOrWhiteSpace(result.ChainOfCustodyLogPath))
                {
                    AppendSessionMessage($"Network chain-of-custody log: {result.ChainOfCustodyLogPath}");
                }
            }
            if (result.ReadErrorChunks > 0)
            {
                AppendSessionMessage(
                    "Image acquisition used zero-fill continuation for unreadable ranges. Treat recovered content as partial in affected spans.");
                if (!string.IsNullOrWhiteSpace(result.UnreadableRangesManifestPath))
                {
                    AppendSessionMessage($"Unreadable-range manifest: {result.UnreadableRangesManifestPath}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            StatusTextBlock.Text = "Image acquisition canceled";
            ThroughputStatusTextBlock.Text = "Throughput: canceled";
            AppendSessionMessage("Image acquisition canceled.");
        }
        catch (Exception ex)
        {
            StatusTextBlock.Text = "Image acquisition failed";
            ThroughputStatusTextBlock.Text = "Throughput: failed";
            AppendSessionMessage($"Image acquisition failed: {ex.Message}");
        }
        finally
        {
            CompleteOperationScope(operationScope);
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
            if (_runtimeEnvironmentProfile.IsWinPe)
            {
                AppendOfflineReadinessDiagnostics(_sources);
            }
        }
    }

    private void DestinationPathTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (_runtimeEnvironmentProfile.IsWinPe)
        {
            _ = TryValidateWinPeOfflineReadiness(_sources, verbose: false);
        }
    }

    private void ValidateSafetyButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshElevationState();
        var result = _safetyValidator.Validate(_selectedSource, DestinationPathTextBox.Text, _isElevated);
        RenderValidation(result);
        if (_runtimeEnvironmentProfile.IsWinPe)
        {
            AppendOfflineReadinessDiagnostics(_sources);
        }
    }

    private async void StartSessionButton_Click(object sender, RoutedEventArgs e)
    {
        _quickScanCandidates.Clear();
        ClearPreviewPanel();
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

        if (!TryValidateWinPeOfflineReadiness(_sources, verbose: true))
        {
            StatusTextBlock.Text = "Session blocked by WinPE offline readiness checks";
            return;
        }

        var selectedSource = _selectedSource;
        var scanMode = ScanModeComboBox.SelectedItem is ScanMode mode ? mode : ScanMode.Quick;
        var quickScanMaxRecords = GetQuickScanMaxRecords();
        var candidateCapacity = GetCandidateCapacity();
        var remoteAgentRequested = (RemoteAgentModeComboBox.SelectedItem is RemoteAgentMode remoteMode)
            && remoteMode != RemoteAgentMode.Disabled;
        if (!TryBuildRaidManualOverride(out var raidManualOverride, out var raidOverrideMessage))
        {
            StatusTextBlock.Text = "Session blocked by invalid RAID override settings";
            _validationOutput.Add($"Error: {raidOverrideMessage}");
            AppendSessionMessage($"RAID override parse error: {raidOverrideMessage}");
            return;
        }
        if (!TryParseRaidMemberSourcePaths(out var raidMemberSourcePaths, out var raidMemberSourceMessage))
        {
            StatusTextBlock.Text = "Session blocked by invalid RAID member source list";
            _validationOutput.Add($"Error: {raidMemberSourceMessage}");
            AppendSessionMessage($"RAID member source parse error: {raidMemberSourceMessage}");
            return;
        }
        Guid? sessionId = null;
        var openedRaidMemberSessionIds = new List<ulong>();
        var activeEngineSessionId = 0UL;
        var activeEngineSessionSizeBytes = 0UL;
        var usingVirtualRaidSession = false;
        var encryptedSourceUnlocked = false;

        if (!ConfirmImageFirstRecommendation(selectedSource, "session initialization"))
        {
            StatusTextBlock.Text = "Session canceled (image-first recommended)";
            return;
        }

        try
        {
            operationToken.ThrowIfCancellationRequested();
            if (IsVssSnapshotSource(selectedSource))
            {
                AppendSessionMessage("VSS snapshot source selected: scan/recovery operations remain read-only.");
            }

            var probePath = ResolveProbePath(selectedSource);
            if (!string.IsNullOrWhiteSpace(probePath))
            {
                operationToken.ThrowIfCancellationRequested();
                var encryptedPreparation = PrepareEncryptedSourceForSession(selectedSource, probePath);
                if (!encryptedPreparation.ContinueSession)
                {
                    StatusTextBlock.Text = "Session blocked by encrypted-source unlock requirements";
                    return;
                }

                encryptedSourceUnlocked = encryptedPreparation.Unlocked;
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
                        activeEngineSessionId = open.SessionId;
                        activeEngineSessionSizeBytes = open.SizeBytes;

                        if (raidMemberSourcePaths.Count > 0)
                        {
                            AppendSessionMessage(
                                $"RAID member source override enabled: assembling from {raidMemberSourcePaths.Count} member source(s).");

                            foreach (var memberPath in raidMemberSourcePaths)
                            {
                                operationToken.ThrowIfCancellationRequested();
                                var memberKind = InferSourceKindFromPath(memberPath);
                                var memberOpen = NativeEngineProbe.OpenSourceReadOnlySession(memberPath, memberKind);
                                AppendSessionMessage(
                                    $"RAID member session open: path={memberPath}, kind={memberKind}, message={memberOpen.Message} (status {memberOpen.StatusCode}).");

                                if (!memberOpen.EngineAvailable || !memberOpen.Opened)
                                {
                                    _validationOutput.Add($"Error: RAID member open failed for '{memberPath}' ({memberOpen.Message}).");
                                    StatusTextBlock.Text = "Session blocked by RAID member open failure";
                                    return;
                                }

                                openedRaidMemberSessionIds.Add(memberOpen.SessionId);
                            }

                            operationToken.ThrowIfCancellationRequested();
                            var virtualOpen = NativeEngineProbe.OpenVirtualRaidSession(openedRaidMemberSessionIds, raidManualOverride);
                            AppendSessionMessage(
                                $"Virtual RAID assembly: {virtualOpen.Message} (status {virtualOpen.StatusCode}).");

                            if (!virtualOpen.EngineAvailable || !virtualOpen.Success || virtualOpen.Metadata is null)
                            {
                                _validationOutput.Add($"Error: Virtual RAID assembly failed ({virtualOpen.Message}).");
                                StatusTextBlock.Text = "Session blocked by RAID virtual assembly";
                                return;
                            }

                            usingVirtualRaidSession = true;
                            activeEngineSessionId = virtualOpen.SessionId;
                            activeEngineSessionSizeBytes = virtualOpen.SizeBytes;
                            var metadata = virtualOpen.Metadata;
                            var orderSummary = metadata.DiskOrder.Count == 0
                                ? "(none)"
                                : string.Join(",", metadata.DiskOrder.Select(value => value.ToString(CultureInfo.InvariantCulture)));
                            AppendSessionMessage(
                                $"Virtual RAID layout details: family={metadata.MetadataFamily}, level={metadata.Level}, members={metadata.MemberCount}, stripe={metadata.StripeSizeBytes}, offset={metadata.DataOffsetBytes}, parity={metadata.ParityRotation}, confidence={metadata.ConfidenceScore}, order={orderSummary}.");
                        }

                        operationToken.ThrowIfCancellationRequested();
                        var preflightBufferSize = GetAlignedBufferLength(open.AlignmentBytes, 4096);
                        var preflightBuffer = new byte[preflightBufferSize];
                        var read = NativeEngineProbe.ReadSourceSessionChunk(activeEngineSessionId, 0, preflightBuffer);
                        AppendSessionMessage($"Engine preflight read: {read.Message} (status {read.StatusCode}, bytes {read.BytesRead}).");

                        if (!read.Success)
                        {
                            _validationOutput.Add($"Error: Engine preflight read failed ({read.Message}).");
                            StatusTextBlock.Text = "Session blocked by engine preflight read";
                            return;
                        }

                        operationToken.ThrowIfCancellationRequested();
                        EngineRaidLayoutProbeResult raidProbe;
                        if (usingVirtualRaidSession)
                        {
                            raidProbe = NativeEngineProbe.ProbeVirtualRaidSession(activeEngineSessionId);
                            AppendSessionMessage($"Virtual RAID layout probe: {raidProbe.Message} (status {raidProbe.StatusCode}).");
                        }
                        else
                        {
                            raidProbe = NativeEngineProbe.ProbeRaidLayoutFromSession(activeEngineSessionId, raidManualOverride);
                            AppendSessionMessage($"RAID layout probe: {raidProbe.Message} (status {raidProbe.StatusCode}).");
                        }

                        if (raidProbe.Success && raidProbe.Metadata is not null)
                        {
                            var metadata = raidProbe.Metadata;
                            var orderSummary = metadata.DiskOrder.Count == 0
                                ? "(none)"
                                : string.Join(",", metadata.DiskOrder.Select(value => value.ToString(CultureInfo.InvariantCulture)));
                            AppendSessionMessage(
                                $"RAID layout details: family={metadata.MetadataFamily}, level={metadata.Level}, members={metadata.MemberCount}, stripe={metadata.StripeSizeBytes}, offset={metadata.DataOffsetBytes}, parity={metadata.ParityRotation}, confidence={metadata.ConfidenceScore}, order={orderSummary}.");

                            var mapping = NativeEngineProbe.MapRaidLogicalOffset(metadata, 0);
                            if (mapping.Success && mapping.Mapping is not null)
                            {
                                var paritySummary = mapping.Mapping.ParityMemberIndex.HasValue
                                    ? mapping.Mapping.ParityMemberIndex.Value.ToString(CultureInfo.InvariantCulture)
                                    : "none";
                                AppendSessionMessage(
                                    $"RAID logical offset 0 -> member {mapping.Mapping.MemberIndex} @ {mapping.Mapping.MemberOffsetBytes} (parity member {paritySummary}).");
                            }
                            else
                            {
                                AppendSessionMessage(
                                    $"RAID logical mapping skipped: {mapping.Message} (status {mapping.StatusCode}).");
                            }

                            if (RaidReverseAssistantCheckBox.IsChecked == true)
                            {
                                var missingMembers = ParseRaidMissingMembers(RaidMissingMembersTextBox.Text);
                                EngineRaidDegradedAssessment? baselineAssessment = null;
                                if (missingMembers is null)
                                {
                                    AppendSessionMessage("RAID degraded assessment skipped: missing-member list is invalid.");
                                }
                                else
                                {
                                    var degraded = NativeEngineProbe.AssessRaidDegradedLayout(metadata, missingMembers, sampleCount: 96);
                                    if (degraded.Success && degraded.Assessment is not null)
                                    {
                                        baselineAssessment = degraded.Assessment;
                                        var assessment = baselineAssessment;
                                        AppendSessionMessage(
                                            $"RAID degraded assessment: missing={assessment.MissingMemberCount}, recoverable={assessment.RecoverableSampleCount}/{assessment.SampleCount} ({assessment.RecoverabilityPercent}%), confidence-penalty={assessment.ConfidencePenalty}. {assessment.Recommendation}");
                                    }
                                    else
                                    {
                                        AppendSessionMessage(
                                            $"RAID degraded assessment failed: {degraded.Message} (status {degraded.StatusCode}).");
                                    }
                                }

                                var suggestions = BuildRaidReverseAssistantOverrides(metadata);
                                if (suggestions.Count == 0)
                                {
                                    AppendSessionMessage("RAID reverse-layout assistant: no alternative layouts generated.");
                                }
                                else
                                {
                                    var normalizedMissingMembers = missingMembers ?? Array.Empty<uint>();
                                    var rankedSuggestions = RankRaidAssistantOverrides(
                                        activeEngineSessionId,
                                        suggestions,
                                        normalizedMissingMembers);
                                    AppendSessionMessage(
                                        $"RAID reverse-layout assistant generated {rankedSuggestions.Count} candidate override profiles for degraded/reversed scenarios.");
                                    for (var index = 0; index < rankedSuggestions.Count; index++)
                                    {
                                        var ranked = rankedSuggestions[index];
                                        var probeSummary = ranked.Probe.Success && ranked.Probe.Metadata is not null
                                            ? $"success family={ranked.Probe.Metadata.MetadataFamily}, level={ranked.Probe.Metadata.Level}, parity={ranked.Probe.Metadata.ParityRotation}, confidence={ranked.Probe.Metadata.ConfidenceScore}"
                                            : $"status {ranked.Probe.StatusCode}";
                                        var degradedSummary = ranked.Degraded.Success && ranked.Degraded.Assessment is not null
                                            ? $"recoverability={ranked.Degraded.Assessment.RecoverabilityPercent}%, penalty={ranked.Degraded.Assessment.ConfidencePenalty}"
                                            : "recoverability=n/a";
                                        AppendSessionMessage(
                                            $"RAID assistant profile {index + 1} [score {ranked.Score}]: {ranked.Suggestion.Description} -> {probeSummary}; {degradedSummary} ({ranked.Probe.Message}).");
                                    }

                                    if (baselineAssessment is not null && rankedSuggestions.Count > 0)
                                    {
                                        var best = rankedSuggestions[0];
                                        if (best.Degraded.Success && best.Degraded.Assessment is not null)
                                        {
                                            var delta = best.Degraded.Assessment.RecoverabilityPercent - baselineAssessment.RecoverabilityPercent;
                                            if (delta >= 10)
                                            {
                                                AppendSessionMessage(
                                                    $"RAID degraded export workflow hint: best assistant override improves recoverability by +{delta}% compared to baseline. Re-run assembly with profile 1 before exporting critical files.");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else if (raidProbe.StatusCode == 142)
                        {
                            _validationOutput.Add($"Error: RAID override invalid ({raidProbe.Message}).");
                            StatusTextBlock.Text = "Session blocked by RAID override";
                            return;
                        }

                        operationToken.ThrowIfCancellationRequested();
                        var quickScanLoaded = false;
                        var ntfsBoot = NativeEngineProbe.ProbeNtfsBootFromSession(activeEngineSessionId);
                        AppendSessionMessage($"NTFS boot probe: {ntfsBoot.Message} (status {ntfsBoot.StatusCode}).");

                        if (ntfsBoot.Success && ntfsBoot.Metadata is not null)
                        {
                            var metadata = ntfsBoot.Metadata;
                            AppendSessionMessage(
                                $"NTFS boot details: sector={metadata.BytesPerSector}, cluster={metadata.ClusterSizeBytes}, MFT offset={metadata.MftOffsetBytes}.");

                            operationToken.ThrowIfCancellationRequested();
                            var quickScan = NativeEngineProbe.QuickScanNtfsFromSession(activeEngineSessionId, maxRecords: checked((uint)quickScanMaxRecords));
                            AppendSessionMessage(
                $"NTFS quick scan: {quickScan.Message} (status {quickScan.StatusCode}, parsed={quickScan.ParsedRecords}, failures={quickScan.ParseFailures}, deleted={quickScan.DeletedRecords}, dirs={quickScan.DirectoryRecords}, named={quickScan.NamedRecords}, resident={quickScan.ResidentAttributeCount}, nonresident={quickScan.NonResidentAttributeCount}, nonresident-data={quickScan.RecordsWithNonResidentData}).");
                            AppendSessionMessage(
                                $"NTFS quick scan USN enrichment: matched={quickScan.UsnEnrichedRecords}, ghost={quickScan.UsnGhostRecords}.");

                            if (quickScan.Success)
                            {
                                operationToken.ThrowIfCancellationRequested();
                                var candidateResult = NativeEngineProbe.GetNtfsQuickScanCandidatesFromSession(
                                    activeEngineSessionId,
                                    maxRecords: checked((uint)quickScanMaxRecords),
                                    candidateCapacity: candidateCapacity);

                                AppendSessionMessage(
                                    $"NTFS quick scan candidates: {candidateResult.Message} (status {candidateResult.StatusCode}, count={candidateResult.Candidates.Count}).");
                                RenderQuickScanCandidates(candidateResult);
                                quickScanLoaded = candidateResult.Success;
                            }
                        }
                        else
                        {
                            operationToken.ThrowIfCancellationRequested();
                            var refsBoot = NativeEngineProbe.ProbeRefsBootFromSession(activeEngineSessionId);
                            AppendSessionMessage($"ReFS boot probe: {refsBoot.Message} (status {refsBoot.StatusCode}).");
                            if (refsBoot.Success && refsBoot.Metadata is not null)
                            {
                                var metadata = refsBoot.Metadata;
                                AppendSessionMessage(
                                    $"ReFS boot details: sector={metadata.BytesPerSector}, cluster={metadata.ClusterSizeBytes}, total-sectors={metadata.TotalSectors}, volume-bytes={metadata.VolumeSizeBytes}, serial=0x{metadata.VolumeSerial:X16}.");
                                var refsCandidates = NativeEngineProbe.GetRefsDeletedCandidatesFromSession(
                                    activeEngineSessionId,
                                    maxEntries: checked((uint)quickScanMaxRecords),
                                    candidateCapacity: candidateCapacity);
                                AppendSessionMessage(
                                    $"ReFS quick scan candidates: {refsCandidates.Message} (status {refsCandidates.StatusCode}, count={refsCandidates.Candidates.Count}).");
                                RenderQuickScanCandidates(refsCandidates);
                                quickScanLoaded = refsCandidates.Success;
                                AppendSessionMessage(
                                    "ReFS source detected. Deleted-candidate metadata scan completed.");
                            }
                            else
                            {
                                operationToken.ThrowIfCancellationRequested();
                                var extSuperblock = NativeEngineProbe.ProbeExtSuperblockFromSession(activeEngineSessionId);
                                AppendSessionMessage($"ext superblock probe: {extSuperblock.Message} (status {extSuperblock.StatusCode}).");
                                if (extSuperblock.Success && extSuperblock.Metadata is not null)
                                {
                                    var metadata = extSuperblock.Metadata;
                                    AppendSessionMessage(
                                        $"{metadata.Filesystem} superblock details: block={metadata.BlockSizeBytes}, inode-size={metadata.InodeSizeBytes}, inodes/group={metadata.InodesPerGroup}, total-inodes={metadata.TotalInodes}, total-blocks={metadata.TotalBlocks}.");

                                    operationToken.ThrowIfCancellationRequested();
                                    var extCandidates = NativeEngineProbe.GetExtDeletedCandidatesFromSession(
                                        activeEngineSessionId,
                                        maxEntries: checked((uint)quickScanMaxRecords),
                                        candidateCapacity: candidateCapacity);
                                    AppendSessionMessage(
                                        $"ext quick scan candidates: {extCandidates.Message} (status {extCandidates.StatusCode}, count={extCandidates.Candidates.Count}).");
                                    RenderQuickScanCandidates(extCandidates, metadata.Filesystem);
                                    quickScanLoaded = extCandidates.Success;
                                }
                                else
                                {
                                    operationToken.ThrowIfCancellationRequested();
                                    var xfsSuperblock = NativeEngineProbe.ProbeXfsSuperblockFromSession(activeEngineSessionId);
                                    AppendSessionMessage($"XFS superblock probe: {xfsSuperblock.Message} (status {xfsSuperblock.StatusCode}).");
                                    if (xfsSuperblock.Success && xfsSuperblock.Metadata is not null)
                                    {
                                        var metadata = xfsSuperblock.Metadata;
                                        AppendSessionMessage(
                                            $"XFS superblock details: block={metadata.BlockSizeBytes}, inode-size={metadata.InodeSizeBytes}, ag-count={metadata.AllocationGroupCount}, data-blocks={metadata.DataBlocks}.");

                                        operationToken.ThrowIfCancellationRequested();
                                        var xfsCandidates = NativeEngineProbe.GetXfsDeletedCandidatesFromSession(
                                            activeEngineSessionId,
                                            maxEntries: checked((uint)quickScanMaxRecords),
                                            candidateCapacity: candidateCapacity);
                                        AppendSessionMessage(
                                            $"XFS quick scan candidates: {xfsCandidates.Message} (status {xfsCandidates.StatusCode}, count={xfsCandidates.Candidates.Count}).");
                                        RenderQuickScanCandidates(xfsCandidates, "XFS");
                                        quickScanLoaded = xfsCandidates.Success;
                                    }
                                    else
                                    {
                                        operationToken.ThrowIfCancellationRequested();
                                        var ufsSuperblock = NativeEngineProbe.ProbeUfsSuperblockFromSession(activeEngineSessionId);
                                        AppendSessionMessage($"UFS superblock probe: {ufsSuperblock.Message} (status {ufsSuperblock.StatusCode}).");
                                        if (ufsSuperblock.Success && ufsSuperblock.Metadata is not null)
                                        {
                                            var metadata = ufsSuperblock.Metadata;
                                            AppendSessionMessage(
                                                $"UFS superblock details: magic=0x{metadata.Magic:X8}, block={metadata.BlockSizeBytes}, fragment={metadata.FragmentSizeBytes}, total-blocks={metadata.TotalBlocks}.");

                                            operationToken.ThrowIfCancellationRequested();
                                            var ufsCandidates = NativeEngineProbe.GetUfsDeletedCandidatesFromSession(
                                                activeEngineSessionId,
                                                maxEntries: checked((uint)quickScanMaxRecords),
                                                candidateCapacity: candidateCapacity);
                                            AppendSessionMessage(
                                                $"UFS quick scan candidates: {ufsCandidates.Message} (status {ufsCandidates.StatusCode}, count={ufsCandidates.Candidates.Count}).");
                                            RenderQuickScanCandidates(ufsCandidates, "UFS");
                                            quickScanLoaded = ufsCandidates.Success;
                                        }
                                        else
                                        {
                                            operationToken.ThrowIfCancellationRequested();
                                            var apfsContainer = NativeEngineProbe.ProbeApfsContainerFromSession(activeEngineSessionId);
                                            AppendSessionMessage($"APFS container probe: {apfsContainer.Message} (status {apfsContainer.StatusCode}).");
                                            if (apfsContainer.Success && apfsContainer.Metadata is not null)
                                            {
                                                var metadata = apfsContainer.Metadata;
                                                AppendSessionMessage(
                                                    $"APFS container details: block={metadata.BlockSizeBytes}, blocks={metadata.BlockCount}, features=0x{metadata.Features:X}, incompat=0x{metadata.IncompatFeatures:X}, oid={metadata.ContainerObjectId}.");

                                                operationToken.ThrowIfCancellationRequested();
                                                var apfsCandidates = NativeEngineProbe.GetApfsDeletedCandidatesFromSession(
                                                    activeEngineSessionId,
                                                    maxEntries: checked((uint)quickScanMaxRecords),
                                                    candidateCapacity: candidateCapacity);
                                                AppendSessionMessage(
                                                    $"APFS quick scan candidates: {apfsCandidates.Message} (status {apfsCandidates.StatusCode}, count={apfsCandidates.Candidates.Count}).");
                                                RenderQuickScanCandidates(apfsCandidates, "APFS");
                                                quickScanLoaded = apfsCandidates.Success;
                                            }
                                            else
                                            {
                                                operationToken.ThrowIfCancellationRequested();
                                                var hfsVolume = NativeEngineProbe.ProbeHfsVolumeHeaderFromSession(activeEngineSessionId);
                                                AppendSessionMessage($"HFS+ volume probe: {hfsVolume.Message} (status {hfsVolume.StatusCode}).");
                                                if (hfsVolume.Success && hfsVolume.Metadata is not null)
                                                {
                                                    var metadata = hfsVolume.Metadata;
                                                    AppendSessionMessage(
                                                        $"HFS+ volume details: signature=0x{metadata.Signature:X4}, version={metadata.Version}, block={metadata.BlockSizeBytes}, total-blocks={metadata.TotalBlocks}, files={metadata.FileCount}, folders={metadata.FolderCount}.");

                                                    operationToken.ThrowIfCancellationRequested();
                                                    var hfsCandidates = NativeEngineProbe.GetHfsDeletedCandidatesFromSession(
                                                        activeEngineSessionId,
                                                        maxEntries: checked((uint)quickScanMaxRecords),
                                                        candidateCapacity: candidateCapacity);
                                                    AppendSessionMessage(
                                                        $"HFS+ quick scan candidates: {hfsCandidates.Message} (status {hfsCandidates.StatusCode}, count={hfsCandidates.Candidates.Count}).");
                                                    RenderQuickScanCandidates(hfsCandidates, "HFS+");
                                                    quickScanLoaded = hfsCandidates.Success;
                                                }
                                                else
                                                {
                                                    operationToken.ThrowIfCancellationRequested();
                                                    var fatBoot = NativeEngineProbe.ProbeFatBootFromSession(activeEngineSessionId);
                                                    AppendSessionMessage($"FAT boot probe: {fatBoot.Message} (status {fatBoot.StatusCode}).");
                                                    if (fatBoot.Success && fatBoot.Metadata is not null)
                                                    {
                                                        var metadata = fatBoot.Metadata;
                                                        AppendSessionMessage(
                                                            $"FAT boot details: fs={metadata.Filesystem}, sector={metadata.BytesPerSector}, cluster={metadata.ClusterSizeBytes}, FAT offset={metadata.FatOffsetBytes}, data offset={metadata.DataRegionOffsetBytes}, root cluster={metadata.RootDirectoryFirstCluster}.");

                                                        operationToken.ThrowIfCancellationRequested();
                                                        var fatCandidates = NativeEngineProbe.GetFatDeletedCandidatesFromSession(
                                                            activeEngineSessionId,
                                                            maxEntries: checked((uint)quickScanMaxRecords),
                                                            candidateCapacity: candidateCapacity);
                                                        AppendSessionMessage(
                                                            $"FAT quick scan candidates: {fatCandidates.Message} (status {fatCandidates.StatusCode}, count={fatCandidates.Candidates.Count}).");
                                                        RenderQuickScanCandidates(fatCandidates, metadata.Filesystem);
                                                        quickScanLoaded = fatCandidates.Success;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if (scanMode == ScanMode.Full)
                        {
                            operationToken.ThrowIfCancellationRequested();
                            var familyFlags = BuildSelectedCarveFamilyFlags();
                            var signaturePack = NativeEngineProbe.GetCarveSignaturePackMetadata();
                            if (signaturePack.Success && signaturePack.Metadata is not null)
                            {
                                var metadata = signaturePack.Metadata;
                                AppendSessionMessage(
                                    $"Carve signature pack: {metadata.PackName} {metadata.PackVersion} ({metadata.FormatCount} formats).");
                            }
                            else if (!signaturePack.EngineAvailable)
                            {
                                AppendSessionMessage($"Carve signature pack metadata unavailable: {signaturePack.Message}.");
                            }

                            var carveResult = RunStreamingCarveScan(
                                activeEngineSessionId,
                                activeEngineSessionSizeBytes,
                                familyFlags,
                                candidateCapacity: Math.Max(candidateCapacity, 256),
                                operationToken);
                            AppendSessionMessage(
                                $"Carving scan: {carveResult.Message} (status {carveResult.StatusCode}, count={carveResult.Candidates.Count}).");
                            AppendCarveCandidates(carveResult);
                        }

                        if (!quickScanLoaded && scanMode != ScanMode.Full)
                        {
                            AppendSessionMessage("No metadata quick-scan candidates were loaded for this source.");
                        }
                    }
                    finally
                    {
                        if (usingVirtualRaidSession)
                        {
                            var closeVirtualStatus = NativeEngineProbe.CloseVirtualRaidSession(activeEngineSessionId);
                            AppendSessionMessage($"Virtual RAID session close status: {closeVirtualStatus}");
                        }

                        foreach (var memberSessionId in openedRaidMemberSessionIds.Distinct())
                        {
                            var memberCloseStatus = NativeEngineProbe.CloseSourceSession(memberSessionId);
                            AppendSessionMessage(
                                $"RAID member session close status: id={memberSessionId}, status={memberCloseStatus}");
                        }

                        var closeStatus = NativeEngineProbe.CloseSourceSession(open.SessionId);
                        AppendSessionMessage($"Engine session close status: {closeStatus}");
                    }
                }
            }

            operationToken.ThrowIfCancellationRequested();
            var sessionSourceClass = ResolveSessionSourceClass(
                usingVirtualRaidSession,
                encryptedSourceUnlocked,
                remoteAgentRequested);
            var signaturePackSet = BuildSessionSignaturePackSet(scanMode);
            var custodyHashChainRef = await BuildSessionCustodyHashChainReferenceAsync(operationToken);
            sessionId = await _sessionStore.CreateSessionAsync(
                selectedSource,
                DestinationPathTextBox.Text,
                scanMode,
                sessionSourceClass,
                signaturePackSet,
                custodyHashChainRef,
                operationToken);
            _activeSessionId = sessionId.Value;
            _activeSessionSourceClass = sessionSourceClass;
            _activeSignaturePackSet = signaturePackSet;
            _activeCustodyHashChainRef = custodyHashChainRef;

            await _sessionLogWriter.CreateSessionLogsAsync(sessionId.Value, operationToken);
            await _sessionLogWriter.LogEventAsync(sessionId.Value, "session_initialized", new
            {
                source_id = selectedSource.Id,
                source_class = sessionSourceClass,
                signature_pack_set = signaturePackSet,
                custody_hash_chain_ref = custodyHashChainRef,
                source_kind = selectedSource.Kind.ToString(),
                source_is_network = selectedSource.IsNetworkSource,
                source_network_protocol = selectedSource.NetworkProtocol,
                source_network_endpoint = selectedSource.NetworkEndpoint,
                destination = DestinationPathTextBox.Text,
                scan_mode = scanMode.ToString(),
            }, operationToken);

            await _sessionLogWriter.LogMessageAsync(sessionId.Value, "Session created and waiting for scan pipeline execution.", operationToken);
            await _sessionStore.UpdateStatusAsync(sessionId.Value, "ready", "Session initialized by UI.", operationToken);

            if (_quickScanCandidates.Count > 0)
            {
                operationToken.ThrowIfCancellationRequested();
                var candidateRows = SnapshotCandidateRecordsFromRows();

                await _sessionStore.ReplaceQuickScanCandidatesAsync(sessionId.Value, candidateRows, operationToken);
                await _sessionLogWriter.LogEventAsync(sessionId.Value, "quick_scan_candidates_persisted", new
                {
                    count = candidateRows.Length,
                }, operationToken);

                var persisted = await _sessionStore.GetQuickScanCandidatesAsync(sessionId.Value, quickScanMaxRecords, operationToken);
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

        var warningLines = result.Issues
            .Select(issue => $"{issue.Severity}: {issue.Message}")
            .ToArray();
        SafetyWarningsListBox.ItemsSource = BuildSafetyWarnings(warningLines);
    }

    private void RenderQuickScanCandidates(EngineNtfsQuickScanCandidatesResult result)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("Candidate load failed: engine result was not successful.");
            return;
        }

        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var evidenceSources = NormalizeEvidenceSourcesForSelectedSource(
                    candidate.EvidenceSources,
                    _selectedSource);

                return new QuickScanCandidateRecord(
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
                    EvidenceSources: evidenceSources,
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
                        candidate.ReconstructedPath,
                        evidenceSources));
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(EngineFatDeletedCandidatesResult result, string filesystem)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("FAT candidate load failed: engine result was not successful.");
            return;
        }

        var evidenceSources = NormalizeFatEvidenceLabel(filesystem);
        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var name = candidate.Name;
                var path = candidate.ReconstructedPath;
                var hasRecoverableCluster = candidate.StartCluster >= 2 || candidate.IsDirectory;
                var candidateStatus = hasRecoverableCluster
                    ? ComputeCandidateStatus(
                        candidate.Deleted,
                        false,
                        candidate.IsDirectory,
                        false,
                        false,
                        false,
                        name,
                        path,
                        evidenceSources)
                    : RecoveryCandidateStatus.Invalid;
                var confidenceReason = hasRecoverableCluster
                    ? $"{evidenceSources} deleted directory-entry candidate from root metadata quick scan."
                    : $"{evidenceSources} deleted directory-entry candidate is missing recoverable start-cluster metadata.";
                return new QuickScanCandidateRecord(
                    Ordinal: index,
                    RecordNumber: BuildFatSyntheticRecordNumber(candidate.StartCluster, index),
                    Deleted: candidate.Deleted,
                    IsGhostRecord: false,
                    Directory: candidate.IsDirectory,
                    NonResidentData: false,
                    HasNamedDataStreams: false,
                    IsCompressed: false,
                    IsSparse: false,
                    IsEncrypted: false,
                    Name: name,
                    OriginalPath: path,
                    ParentRecordNumber: candidate.StartCluster,
                    DataSizeBytes: candidate.SizeBytes,
                    AllocatedSizeBytes: null,
                    FileAttributes: null,
                    CreatedFileTimeUtc: null,
                    ModifiedFileTimeUtc: null,
                    MftModifiedFileTimeUtc: null,
                    AccessedFileTimeUtc: null,
                    EvidenceSources: evidenceSources,
                    ConfidenceTier: "Medium",
                    ConfidenceReason: confidenceReason,
                    CandidateStatus: candidateStatus);
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(EngineRefsDeletedCandidatesResult result)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("ReFS candidate load failed: engine result was not successful.");
            return;
        }

        const string evidenceSources = "ReFS";
        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var hasObjectId = candidate.ObjectId != 0;
                var name = string.IsNullOrWhiteSpace(candidate.Name)
                    ? $"refs-object-{candidate.ObjectId}"
                    : candidate.Name;
                var path = string.IsNullOrWhiteSpace(candidate.ReconstructedPath)
                    ? $".\\{name}"
                    : candidate.ReconstructedPath;
                var candidateStatus = candidate.Deleted && hasObjectId
                    ? ComputeCandidateStatus(
                        candidate.Deleted,
                        false,
                        false,
                        false,
                        false,
                        false,
                        name,
                        path,
                        evidenceSources)
                    : RecoveryCandidateStatus.Invalid;
                var confidenceReason = candidate.Deleted && hasObjectId
                    ? "ReFS deleted candidate inferred from journal-style metadata records with byte-export attempt when payload descriptors are available."
                    : "ReFS candidate is missing required deleted/object-id metadata.";
                return new QuickScanCandidateRecord(
                    Ordinal: index,
                    RecordNumber: BuildRefsSyntheticRecordNumber(candidate.ObjectId, index),
                    Deleted: candidate.Deleted,
                    IsGhostRecord: false,
                    Directory: false,
                    NonResidentData: false,
                    HasNamedDataStreams: false,
                    IsCompressed: false,
                    IsSparse: false,
                    IsEncrypted: false,
                    Name: name,
                    OriginalPath: path,
                    ParentRecordNumber: candidate.ObjectId > 0 ? candidate.ObjectId : null,
                    DataSizeBytes: candidate.SizeBytes > 0 ? candidate.SizeBytes : null,
                    AllocatedSizeBytes: null,
                    FileAttributes: null,
                    CreatedFileTimeUtc: null,
                    ModifiedFileTimeUtc: null,
                    MftModifiedFileTimeUtc: null,
                    AccessedFileTimeUtc: null,
                    EvidenceSources: evidenceSources,
                    ConfidenceTier: "Medium",
                    ConfidenceReason: confidenceReason,
                    CandidateStatus: candidateStatus);
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(EngineExtDeletedCandidatesResult result, string filesystem)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("ext candidate load failed: engine result was not successful.");
            return;
        }

        var evidenceSources = string.IsNullOrWhiteSpace(filesystem) ? "ext4" : filesystem.Trim();
        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var name = string.IsNullOrWhiteSpace(candidate.Name)
                    ? $"ext-entry-{candidate.EntryOffsetBytes}"
                    : candidate.Name;
                var path = string.IsNullOrWhiteSpace(candidate.ReconstructedPath)
                    ? $".\\{name}"
                    : candidate.ReconstructedPath;
                var hasRecoverableInode = candidate.InodeNumber > 0;
                var candidateStatus = candidate.Deleted && hasRecoverableInode
                    ? ComputeCandidateStatus(
                        candidate.Deleted,
                        false,
                        candidate.IsDirectory,
                        false,
                        false,
                        false,
                        name,
                        path,
                        evidenceSources)
                    : RecoveryCandidateStatus.Invalid;
                var confidenceReason = candidate.Deleted && hasRecoverableInode
                    ? $"{evidenceSources} deleted inode candidate from metadata scan with inode-backed recovery path."
                    : $"{evidenceSources} candidate is missing deleted/inode metadata required for recovery.";
                return new QuickScanCandidateRecord(
                    Ordinal: index,
                    RecordNumber: BuildExtSyntheticRecordNumber(candidate.EntryOffsetBytes, index),
                    Deleted: candidate.Deleted,
                    IsGhostRecord: false,
                    Directory: candidate.IsDirectory,
                    NonResidentData: false,
                    HasNamedDataStreams: false,
                    IsCompressed: false,
                    IsSparse: false,
                    IsEncrypted: false,
                    Name: name,
                    OriginalPath: path,
                    ParentRecordNumber: candidate.InodeNumber > 0 ? candidate.InodeNumber : null,
                    DataSizeBytes: candidate.SizeBytes > 0 ? candidate.SizeBytes : null,
                    AllocatedSizeBytes: null,
                    FileAttributes: null,
                    CreatedFileTimeUtc: null,
                    ModifiedFileTimeUtc: null,
                    MftModifiedFileTimeUtc: null,
                    AccessedFileTimeUtc: null,
                    EvidenceSources: evidenceSources,
                    ConfidenceTier: "Low",
                    ConfidenceReason: confidenceReason,
                    CandidateStatus: RecoveryCandidateStatus.Invalid);
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(EngineXfsDeletedCandidatesResult result, string filesystem)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("XFS candidate load failed: engine result was not successful.");
            return;
        }

        var evidenceSources = string.IsNullOrWhiteSpace(filesystem) ? "XFS" : filesystem.Trim();
        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var name = string.IsNullOrWhiteSpace(candidate.Name)
                    ? $"xfs-inode-{candidate.InodeNumber}"
                    : candidate.Name;
                var path = string.IsNullOrWhiteSpace(candidate.ReconstructedPath)
                    ? $".\\{name}"
                    : candidate.ReconstructedPath;
                var hasInode = candidate.InodeNumber > 0;
                var candidateStatus = candidate.Deleted && hasInode
                    ? ComputeCandidateStatus(
                        candidate.Deleted,
                        false,
                        candidate.IsDirectory,
                        false,
                        false,
                        false,
                        name,
                        path,
                        evidenceSources)
                    : RecoveryCandidateStatus.Invalid;
                var confidenceReason = candidate.Deleted && hasInode
                    ? $"{evidenceSources} deleted inode candidate attempts full byte export first and falls back to metadata-manifest export when layout is unsupported."
                    : $"{evidenceSources} candidate is missing deleted/inode metadata.";
                return new QuickScanCandidateRecord(
                    Ordinal: index,
                    RecordNumber: BuildXfsSyntheticRecordNumber(candidate.InodeNumber, index),
                    Deleted: candidate.Deleted,
                    IsGhostRecord: false,
                    Directory: candidate.IsDirectory,
                    NonResidentData: false,
                    HasNamedDataStreams: false,
                    IsCompressed: false,
                    IsSparse: false,
                    IsEncrypted: false,
                    Name: name,
                    OriginalPath: path,
                    ParentRecordNumber: candidate.InodeNumber > 0 ? candidate.InodeNumber : null,
                    DataSizeBytes: candidate.SizeBytes > 0 ? candidate.SizeBytes : null,
                    AllocatedSizeBytes: null,
                    FileAttributes: null,
                    CreatedFileTimeUtc: null,
                    ModifiedFileTimeUtc: null,
                    MftModifiedFileTimeUtc: null,
                    AccessedFileTimeUtc: null,
                    EvidenceSources: evidenceSources,
                    ConfidenceTier: "Low",
                    ConfidenceReason: confidenceReason,
                    CandidateStatus: candidateStatus);
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(EngineUfsDeletedCandidatesResult result, string filesystem)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("UFS candidate load failed: engine result was not successful.");
            return;
        }

        var evidenceSources = string.IsNullOrWhiteSpace(filesystem) ? "UFS" : filesystem.Trim();
        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var name = string.IsNullOrWhiteSpace(candidate.Name)
                    ? $"ufs-inode-{candidate.InodeNumber}"
                    : candidate.Name;
                var path = string.IsNullOrWhiteSpace(candidate.ReconstructedPath)
                    ? $".\\{name}"
                    : candidate.ReconstructedPath;
                var hasInode = candidate.InodeNumber > 0;
                var candidateStatus = candidate.Deleted && hasInode
                    ? ComputeCandidateStatus(
                        candidate.Deleted,
                        false,
                        candidate.IsDirectory,
                        false,
                        false,
                        false,
                        name,
                        path,
                        evidenceSources)
                    : RecoveryCandidateStatus.Invalid;
                var confidenceReason = candidate.Deleted && hasInode
                    ? $"{evidenceSources} deleted inode candidate attempts full byte export first and falls back to metadata-manifest export when layout is unsupported."
                    : $"{evidenceSources} candidate is missing deleted/inode metadata.";
                return new QuickScanCandidateRecord(
                    Ordinal: index,
                    RecordNumber: BuildUfsSyntheticRecordNumber(candidate.InodeNumber, index),
                    Deleted: candidate.Deleted,
                    IsGhostRecord: false,
                    Directory: candidate.IsDirectory,
                    NonResidentData: false,
                    HasNamedDataStreams: false,
                    IsCompressed: false,
                    IsSparse: false,
                    IsEncrypted: false,
                    Name: name,
                    OriginalPath: path,
                    ParentRecordNumber: candidate.InodeNumber > 0 ? candidate.InodeNumber : null,
                    DataSizeBytes: candidate.SizeBytes > 0 ? candidate.SizeBytes : null,
                    AllocatedSizeBytes: null,
                    FileAttributes: null,
                    CreatedFileTimeUtc: null,
                    ModifiedFileTimeUtc: null,
                    MftModifiedFileTimeUtc: null,
                    AccessedFileTimeUtc: null,
                    EvidenceSources: evidenceSources,
                    ConfidenceTier: "Low",
                    ConfidenceReason: confidenceReason,
                    CandidateStatus: candidateStatus);
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(EngineApfsDeletedCandidatesResult result, string filesystem)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("APFS candidate load failed: engine result was not successful.");
            return;
        }

        var evidenceSources = string.IsNullOrWhiteSpace(filesystem) ? "APFS" : filesystem.Trim();
        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var name = string.IsNullOrWhiteSpace(candidate.Name)
                    ? $"apfs-cnid-{candidate.Cnid}"
                    : candidate.Name;
                var path = string.IsNullOrWhiteSpace(candidate.ReconstructedPath)
                    ? $".\\{name}"
                    : candidate.ReconstructedPath;
                var hasCnid = candidate.Cnid > 0;
                var candidateStatus = candidate.Deleted && hasCnid
                    ? ComputeCandidateStatus(
                        candidate.Deleted,
                        false,
                        candidate.IsDirectory,
                        false,
                        false,
                        false,
                        name,
                        path,
                        evidenceSources)
                    : RecoveryCandidateStatus.Invalid;
                var confidenceReason = candidate.Deleted && hasCnid
                    ? $"{evidenceSources} deleted metadata tombstone candidate attempts full byte export first and falls back to metadata-manifest export when layout is unsupported."
                    : $"{evidenceSources} candidate is missing deleted/CNID metadata.";
                return new QuickScanCandidateRecord(
                    Ordinal: index,
                    RecordNumber: BuildApfsSyntheticRecordNumber(candidate.Cnid, index),
                    Deleted: candidate.Deleted,
                    IsGhostRecord: false,
                    Directory: candidate.IsDirectory,
                    NonResidentData: false,
                    HasNamedDataStreams: false,
                    IsCompressed: false,
                    IsSparse: false,
                    IsEncrypted: false,
                    Name: name,
                    OriginalPath: path,
                    ParentRecordNumber: candidate.Cnid > 0 ? candidate.Cnid : null,
                    DataSizeBytes: candidate.SizeBytes > 0 ? candidate.SizeBytes : null,
                    AllocatedSizeBytes: null,
                    FileAttributes: null,
                    CreatedFileTimeUtc: null,
                    ModifiedFileTimeUtc: null,
                    MftModifiedFileTimeUtc: null,
                    AccessedFileTimeUtc: null,
                    EvidenceSources: evidenceSources,
                    ConfidenceTier: "Low",
                    ConfidenceReason: confidenceReason,
                    CandidateStatus: candidateStatus);
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(EngineHfsDeletedCandidatesResult result, string filesystem)
    {
        if (!result.Success)
        {
            _quickScanCandidates.Clear();
            _candidateClusterCount = 0;
            _candidateDedupedCount = 0;
            RefreshCandidateView();
            AppendCandidateActivity("HFS+ candidate load failed: engine result was not successful.");
            return;
        }

        var evidenceSources = string.IsNullOrWhiteSpace(filesystem) ? "HFS+" : filesystem.Trim();
        var mapped = result.Candidates
            .Select((candidate, index) =>
            {
                var name = string.IsNullOrWhiteSpace(candidate.Name)
                    ? $"hfs-cnid-{candidate.Cnid}"
                    : candidate.Name;
                var path = string.IsNullOrWhiteSpace(candidate.ReconstructedPath)
                    ? $".\\{name}"
                    : candidate.ReconstructedPath;
                var hasCnid = candidate.Cnid > 0;
                var candidateStatus = candidate.Deleted && hasCnid
                    ? ComputeCandidateStatus(
                        candidate.Deleted,
                        false,
                        candidate.IsDirectory,
                        false,
                        false,
                        false,
                        name,
                        path,
                        evidenceSources)
                    : RecoveryCandidateStatus.Invalid;
                var confidenceReason = candidate.Deleted && hasCnid
                    ? $"{evidenceSources} deleted catalog tombstone candidate attempts full byte export first and falls back to metadata-manifest export when layout is unsupported."
                    : $"{evidenceSources} candidate is missing deleted/CNID metadata.";
                return new QuickScanCandidateRecord(
                    Ordinal: index,
                    RecordNumber: BuildHfsSyntheticRecordNumber(candidate.Cnid, index),
                    Deleted: candidate.Deleted,
                    IsGhostRecord: false,
                    Directory: candidate.IsDirectory,
                    NonResidentData: false,
                    HasNamedDataStreams: false,
                    IsCompressed: false,
                    IsSparse: false,
                    IsEncrypted: false,
                    Name: name,
                    OriginalPath: path,
                    ParentRecordNumber: candidate.Cnid,
                    DataSizeBytes: candidate.SizeBytes > 0 ? candidate.SizeBytes : null,
                    AllocatedSizeBytes: null,
                    FileAttributes: null,
                    CreatedFileTimeUtc: null,
                    ModifiedFileTimeUtc: null,
                    MftModifiedFileTimeUtc: null,
                    AccessedFileTimeUtc: null,
                    EvidenceSources: evidenceSources,
                    ConfidenceTier: "Low",
                    ConfidenceReason: confidenceReason,
                    CandidateStatus: candidateStatus);
            })
            .ToArray();

        RenderQuickScanCandidates(mapped);
    }

    private void RenderQuickScanCandidates(IReadOnlyList<QuickScanCandidateRecord> candidates)
    {
        var processed = _candidatePostProcessor.Process(candidates);
        var previouslySelectedKeys = _quickScanCandidates
            .Where(existing => existing.IsSelected)
            .Select(BuildCandidateSelectionKey)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        _quickScanCandidates.Clear();

        foreach (var entry in processed.Candidates)
        {
            var candidate = entry.Candidate;
            var defaultSelection = candidate.Deleted && !candidate.IsGhostRecord && !IsCarveEvidence(candidate.EvidenceSources);
            var selectionKey = BuildCandidateSelectionKey(candidate.RecordNumber, candidate.Name, candidate.OriginalPath);
            _quickScanCandidates.Add(new QuickScanCandidateRow
            {
                Ordinal = candidate.Ordinal,
                IsSelected = previouslySelectedKeys.Count == 0
                    ? defaultSelection
                    : previouslySelectedKeys.Contains(selectionKey),
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
                RecoveredPath = string.Empty,
                FileType = DetermineFileType(candidate),
                ParentRecord = candidate.ParentRecordNumber?.ToString() ?? string.Empty,
                ClusterId = entry.ClusterId,
                ClusterSize = entry.ClusterSize,
                DeduplicatedCount = entry.DeduplicatedCount,
                DataSizeBytes = candidate.DataSizeBytes,
                AllocatedSizeBytes = candidate.AllocatedSizeBytes,
                FileAttributes = candidate.FileAttributes,
                CreatedFileTimeUtc = candidate.CreatedFileTimeUtc,
                ModifiedFileTimeUtc = candidate.ModifiedFileTimeUtc,
                MftModifiedFileTimeUtc = candidate.MftModifiedFileTimeUtc,
                AccessedFileTimeUtc = candidate.AccessedFileTimeUtc,
                CarveOffsetBytes = candidate.CarveOffsetBytes,
                CarveLengthBytes = candidate.CarveLengthBytes,
                CarveFormat = candidate.CarveFormat ?? string.Empty,
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

        _candidateClusterCount = processed.ClusterCount;
        _candidateDedupedCount = processed.RemovedDuplicateCount;
        PopulateCandidateFilterOptions();
        ClearPreviewPanel();
        RefreshCandidateView();
        AppendCandidateActivity(
            $"Loaded {_quickScanCandidates.Count} candidate rows (input={processed.InputCount}, clusters={processed.ClusterCount}, deduped={processed.RemovedDuplicateCount}).");
    }

    private uint BuildSelectedCarveFamilyFlags()
    {
        var flags = 0u;
        if (CarveImagesCheckBox.IsChecked == true)
        {
            flags |= NativeEngineProbe.CarveFamilyImages;
        }
        if (CarveDocumentsCheckBox.IsChecked == true)
        {
            flags |= NativeEngineProbe.CarveFamilyDocuments;
        }
        if (CarveArchivesCheckBox.IsChecked == true)
        {
            flags |= NativeEngineProbe.CarveFamilyArchives;
        }
        if (CarveOfficeCheckBox.IsChecked == true)
        {
            flags |= NativeEngineProbe.CarveFamilyOffice;
        }
        if (CarveMediaCheckBox.IsChecked == true)
        {
            flags |= NativeEngineProbe.CarveFamilyMedia;
        }
        if (CarveArtifactsCheckBox.IsChecked == true)
        {
            flags |= NativeEngineProbe.CarveFamilyArtifacts;
        }

        if (flags == 0)
        {
            flags = NativeEngineProbe.CarveFamilyImages
                | NativeEngineProbe.CarveFamilyDocuments
                | NativeEngineProbe.CarveFamilyArchives
                | NativeEngineProbe.CarveFamilyOffice
                | NativeEngineProbe.CarveFamilyMedia;
        }

        return flags;
    }

    private string BuildSessionSignaturePackSet(ScanMode scanMode)
    {
        if (scanMode != ScanMode.Full)
        {
            return "pack=none;families=none";
        }

        var signaturePack = NativeEngineProbe.GetCarveSignaturePackMetadata();
        var packName = "core-signatures";
        var packVersion = "unknown";
        if (signaturePack.Success && signaturePack.Metadata is not null)
        {
            packName = string.IsNullOrWhiteSpace(signaturePack.Metadata.PackName)
                ? packName
                : signaturePack.Metadata.PackName;
            packVersion = string.IsNullOrWhiteSpace(signaturePack.Metadata.PackVersion)
                ? packVersion
                : signaturePack.Metadata.PackVersion;
        }

        var families = string.Join("|", DescribeCarveFamilies(BuildSelectedCarveFamilyFlags()));
        return $"pack={packName}@{packVersion};families={families}";
    }

    private static IReadOnlyList<string> DescribeCarveFamilies(uint flags)
    {
        var labels = new List<string>();
        if ((flags & NativeEngineProbe.CarveFamilyImages) != 0)
        {
            labels.Add("images");
        }
        if ((flags & NativeEngineProbe.CarveFamilyDocuments) != 0)
        {
            labels.Add("documents");
        }
        if ((flags & NativeEngineProbe.CarveFamilyArchives) != 0)
        {
            labels.Add("archives");
        }
        if ((flags & NativeEngineProbe.CarveFamilyOffice) != 0)
        {
            labels.Add("office");
        }
        if ((flags & NativeEngineProbe.CarveFamilyMedia) != 0)
        {
            labels.Add("media");
        }
        if ((flags & NativeEngineProbe.CarveFamilyArtifacts) != 0)
        {
            labels.Add("artifacts");
        }

        return labels.Count == 0 ? ["none"] : labels;
    }

    private async Task<string?> BuildSessionCustodyHashChainReferenceAsync(CancellationToken cancellationToken)
    {
        var chainPath = ChainOfCustodyLogPathTextBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(chainPath))
        {
            return null;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(chainPath);
        }
        catch
        {
            return null;
        }

        if (!File.Exists(fullPath))
        {
            return $"jsonl-path:{fullPath}";
        }

        await using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: 128 * 1024,
            useAsync: true);
        var hashBytes = await SHA256.HashDataAsync(stream, cancellationToken);
        var hashHex = Convert.ToHexString(hashBytes).ToLowerInvariant();
        return $"jsonl-sha256:{hashHex};path={fullPath}";
    }

    private static EngineCarveCandidatesResult RunStreamingCarveScan(
        ulong sessionId,
        ulong sourceSizeBytes,
        uint familyFlags,
        int candidateCapacity,
        CancellationToken operationToken)
    {
        var unique = new HashSet<string>(StringComparer.Ordinal);
        var aggregated = new List<EngineCarveCandidate>();
        var windowsScanned = 0;

        // Unknown source sizes (or zero-sized probes) run one bounded carve window.
        var unknownSourceLength = sourceSizeBytes == 0;
        var totalBytes = sourceSizeBytes;
        var offset = 0UL;

        while (unknownSourceLength || offset < totalBytes)
        {
            operationToken.ThrowIfCancellationRequested();

            var windowLength = unknownSourceLength
                ? FullScanCarveChunkBytes + FullScanCarveOverlapBytes
                : Math.Min(totalBytes - offset, FullScanCarveChunkBytes + FullScanCarveOverlapBytes);
            var windowResult = NativeEngineProbe.GetCarveCandidatesFromSessionWindow(
                sessionId,
                familyFlags,
                windowOffsetBytes: offset,
                windowLengthBytes: windowLength,
                candidateCapacity: candidateCapacity);

            windowsScanned++;
            if (!windowResult.Success)
            {
                var failedMessage = $"Streaming carve window at 0x{offset:X} failed: {windowResult.Message}";
                return new EngineCarveCandidatesResult(
                    windowResult.EngineAvailable,
                    false,
                    aggregated,
                    failedMessage,
                    windowResult.StatusCode);
            }

            foreach (var candidate in windowResult.Candidates)
            {
                var key = $"{candidate.OffsetBytes:X16}|{candidate.LengthBytes:X16}|{candidate.Format}";
                if (unique.Add(key))
                {
                    aggregated.Add(candidate);
                }
            }

            if (unknownSourceLength)
            {
                break;
            }

            var remaining = totalBytes - offset;
            if (remaining <= FullScanCarveChunkBytes)
            {
                break;
            }

            var nextOffset = offset + FullScanCarveChunkBytes;
            if (nextOffset <= offset)
            {
                break;
            }

            offset = nextOffset;
        }

        aggregated.Sort((left, right) => left.OffsetBytes.CompareTo(right.OffsetBytes));
        var message = $"Streaming carve scan completed across {windowsScanned} window(s).";
        return new EngineCarveCandidatesResult(
            true,
            true,
            aggregated,
            message,
            0);
    }

    private void AppendCarveCandidates(EngineCarveCandidatesResult result)
    {
        if (!result.Success)
        {
            AppendCandidateActivity($"Carving candidates not loaded: {result.Message} (status {result.StatusCode}).");
            return;
        }

        if (result.Candidates.Count == 0)
        {
            return;
        }

        var combined = SnapshotCandidateRecordsFromRows().ToList();
        var baseOrdinal = combined.Count;
        for (var index = 0; index < result.Candidates.Count; index++)
        {
            var candidate = result.Candidates[index];
            var format = string.IsNullOrWhiteSpace(candidate.Format) ? "bin" : candidate.Format;
            var suggestedName = string.IsNullOrWhiteSpace(candidate.SuggestedName)
                ? $"carve_{candidate.OffsetBytes:X16}.{format}"
                : candidate.SuggestedName;

            combined.Add(new QuickScanCandidateRecord(
                Ordinal: baseOrdinal + index,
                RecordNumber: BuildSyntheticRecordNumber(candidate.OffsetBytes, index),
                Deleted: false,
                IsGhostRecord: false,
                Directory: false,
                NonResidentData: false,
                HasNamedDataStreams: false,
                IsCompressed: false,
                IsSparse: false,
                IsEncrypted: false,
                Name: suggestedName,
                OriginalPath: $@"Carved\{suggestedName}",
                ParentRecordNumber: null,
                DataSizeBytes: candidate.LengthBytes,
                AllocatedSizeBytes: null,
                FileAttributes: null,
                CreatedFileTimeUtc: null,
                ModifiedFileTimeUtc: null,
                MftModifiedFileTimeUtc: null,
                AccessedFileTimeUtc: null,
                CarveOffsetBytes: candidate.OffsetBytes,
                CarveLengthBytes: candidate.LengthBytes,
                CarveFormat: format,
                EvidenceSources: "Carve",
                ConfidenceTier: candidate.ConfidenceTier,
                CandidateStatus: RecoveryCandidateStatus.Partial,
                ConfidenceReason: candidate.ConfidenceReason,
                RecoveryDiagnostics: candidate.Partial
                    ? "Candidate marked partial by carving validator."
                    : string.Empty));
        }

        RenderQuickScanCandidates(combined);
        AppendCandidateActivity($"Appended {result.Candidates.Count} carve candidates.");
    }

    private QuickScanCandidateRecord[] SnapshotCandidateRecordsFromRows()
    {
        return _quickScanCandidates
            .Select(row =>
            {
                ulong? parentRecord = null;
                if (!string.IsNullOrWhiteSpace(row.ParentRecord)
                    && ulong.TryParse(row.ParentRecord, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedParent))
                {
                    parentRecord = parsedParent;
                }

                return new QuickScanCandidateRecord(
                    Ordinal: row.Ordinal,
                    RecordNumber: row.RecordNumber,
                    Deleted: row.Deleted,
                    IsGhostRecord: row.IsGhostRecord,
                    Directory: row.Directory,
                    NonResidentData: row.NonResidentData,
                    HasNamedDataStreams: row.HasNamedDataStreams,
                    IsCompressed: row.IsCompressed,
                    IsSparse: row.IsSparse,
                    IsEncrypted: row.IsEncrypted,
                    Name: row.Name,
                    OriginalPath: row.OriginalPath,
                    ParentRecordNumber: parentRecord,
                    DataSizeBytes: row.DataSizeBytes,
                    AllocatedSizeBytes: row.AllocatedSizeBytes,
                    FileAttributes: row.FileAttributes,
                    CreatedFileTimeUtc: row.CreatedFileTimeUtc,
                    ModifiedFileTimeUtc: row.ModifiedFileTimeUtc,
                    MftModifiedFileTimeUtc: row.MftModifiedFileTimeUtc,
                    AccessedFileTimeUtc: row.AccessedFileTimeUtc,
                    EvidenceSources: row.EvidenceSource,
                    ConfidenceTier: row.ConfidenceTier,
                    ConfidenceReason: row.ConfidenceReason,
                    CandidateStatus: row.CandidateStatus,
                    RecoveryDiagnostics: string.IsNullOrWhiteSpace(row.RecoveryDiagnostics) ? null : row.RecoveryDiagnostics,
                    LastRecoveryStatusCode: row.LastRecoveryStatusCode,
                    LastRecoveryDiagnosticsFlags: row.LastRecoveryDiagnosticsFlags,
                    LastRecoveredBytes: row.LastRecoveredBytes,
                    LastRecoveryPartial: row.LastRecoveryPartial,
                    CarveOffsetBytes: row.CarveOffsetBytes,
                    CarveLengthBytes: row.CarveLengthBytes,
                    CarveFormat: string.IsNullOrWhiteSpace(row.CarveFormat) ? null : row.CarveFormat);
            })
            .ToArray();
    }

    private static uint BuildSyntheticRecordNumber(ulong offsetBytes, int ordinal)
    {
        var folded = (uint)(offsetBytes ^ (offsetBytes >> 32));
        return unchecked(0xC000_0000u | ((folded + (uint)ordinal) & 0x3FFF_FFFFu));
    }

    private static string NormalizeEvidenceSourcesForSelectedSource(
        string evidenceSources,
        SourceCandidate? selectedSource)
    {
        var normalized = string.IsNullOrWhiteSpace(evidenceSources) ? "MFT" : evidenceSources;
        if (!IsVssSnapshotSource(selectedSource))
        {
            return normalized;
        }

        var hasVss = normalized
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(value => string.Equals(value, "VSS", StringComparison.OrdinalIgnoreCase));
        if (hasVss)
        {
            return normalized;
        }

        return $"{normalized}, VSS";
    }

    private static bool IsVssSnapshotSource(SourceCandidate? source)
    {
        return source is not null
            && source.Id.StartsWith("vss:", StringComparison.OrdinalIgnoreCase);
    }

    private bool ConfirmImageFirstRecommendation(SourceCandidate source, string operationName)
    {
        if (source.Kind == RecoverySourceKind.ImageFile || IsVssSnapshotSource(source))
        {
            return true;
        }

        var sourceLabel = string.IsNullOrWhiteSpace(source.DisplayName)
            ? source.Kind.ToString()
            : source.DisplayName;
        var result = System.Windows.MessageBox.Show(
            this,
            "Recommended workflow is to acquire a forensic image first and run scan/recovery from that image."
                + Environment.NewLine + Environment.NewLine
                + $"Selected source: {sourceLabel}" + Environment.NewLine
                + $"Requested operation: {operationName}" + Environment.NewLine + Environment.NewLine
                + "Continue directly on the live source?",
            "Image-First Recommendation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (result != MessageBoxResult.Yes)
        {
            AppendSessionMessage($"Canceled {operationName}: image-first recommendation not accepted.");
        }

        return result == MessageBoxResult.Yes;
    }

    private void InitializeCandidateFilterControls()
    {
        FilterFileTypeComboBox.ItemsSource = new[] { "All" };
        FilterStatusComboBox.ItemsSource = new[] { "All", "full", "partial", "invalid", "overwritten-risk" };
        FilterEvidenceComboBox.ItemsSource = new[]
        {
            "All",
            "MFT",
            "USN",
            "VSS",
            "ReFS",
            "ext4",
            "XFS",
            "UFS",
            "APFS",
            "HFS+",
            "FAT32",
            "exFAT",
            "Carve"
        };
        FilterConfidenceComboBox.ItemsSource = new[] { "All", "Very high", "High", "Medium", "Low", "Very low" };

        FilterFileTypeComboBox.SelectedIndex = 0;
        FilterStatusComboBox.SelectedIndex = 0;
        FilterEvidenceComboBox.SelectedIndex = 0;
        FilterConfidenceComboBox.SelectedIndex = 0;
    }

    private void InitializeSafetyWarningsPage()
    {
        SafetyWarningsListBox.ItemsSource = BuildSafetyWarnings(Array.Empty<string>());
        DiagnosticsPageTextBox.Text = "Diagnostics page initialized." + Environment.NewLine;
    }

    private static IReadOnlyList<string> BuildSafetyWarnings(IReadOnlyList<string> validationIssues)
    {
        var warnings = new List<string>
        {
            "Source access remains read-only. No writes are performed to the source device.",
            "Recovered files are written only to destination folders outside the source volume.",
            "Do not recover to the same disk/partition to avoid overwrite risk.",
            "Encrypted/EFS/BitLocker content may require credentials and can produce partial recovery."
        };

        foreach (var issue in validationIssues)
        {
            warnings.Add(issue);
        }

        return warnings;
    }

    private static string DetermineFileType(QuickScanCandidateRecord candidate)
    {
        if (!string.IsNullOrWhiteSpace(candidate.CarveFormat))
        {
            return candidate.CarveFormat.Trim().TrimStart('.').ToLowerInvariant();
        }

        var ext = Path.GetExtension(candidate.Name ?? string.Empty);
        if (string.IsNullOrWhiteSpace(ext))
        {
            ext = Path.GetExtension(candidate.OriginalPath ?? string.Empty);
        }

        if (string.IsNullOrWhiteSpace(ext))
        {
            return "unknown";
        }

        return ext.Trim().TrimStart('.').ToLowerInvariant();
    }

    private bool TryGetNetworkAcquisitionSettings(
        out int constrainedNetworkChunkSizeBytes,
        out long? maxNetworkThroughputBytesPerSecond,
        out RemoteAgentMode remoteAgentMode,
        out string? remoteAgentEndpoint,
        out string? chainOfCustodyLogPath,
        out string errorMessage)
    {
        errorMessage = string.Empty;
        maxNetworkThroughputBytesPerSecond = null;
        chainOfCustodyLogPath = null;

        if (!TryParsePositiveInt(
            ConstrainedNetworkChunkKiBTextBox.Text,
            min: 64,
            max: 16 * 1024,
            fallback: DefaultNetworkChunkKiB,
            out var constrainedChunkKiB))
        {
            errorMessage = "Network chunk size must be an integer between 64 and 16384 KiB.";
            constrainedNetworkChunkSizeBytes = DefaultNetworkChunkKiB * 1024;
            remoteAgentMode = RemoteAgentMode.Disabled;
            remoteAgentEndpoint = null;
            return false;
        }

        constrainedNetworkChunkSizeBytes = constrainedChunkKiB * 1024;
        remoteAgentMode = RemoteAgentModeComboBox.SelectedItem is RemoteAgentMode selectedMode
            ? selectedMode
            : RemoteAgentMode.Disabled;
        remoteAgentEndpoint = string.IsNullOrWhiteSpace(RemoteAgentEndpointTextBox.Text)
            ? null
            : RemoteAgentEndpointTextBox.Text.Trim();

        if (remoteAgentMode == RemoteAgentMode.Required && string.IsNullOrWhiteSpace(remoteAgentEndpoint))
        {
            errorMessage = "Remote agent endpoint is required when mode is Required.";
            return false;
        }

        var throughputRaw = MaxNetworkThroughputMiBTextBox.Text?.Trim();
        if (!string.IsNullOrWhiteSpace(throughputRaw))
        {
            if (!double.TryParse(
                throughputRaw,
                NumberStyles.Float,
                CultureInfo.InvariantCulture,
                out var throughputMiB)
                || throughputMiB <= 0
                || throughputMiB > 10_000)
            {
                errorMessage = "Max network throughput must be a positive number in MiB/s.";
                return false;
            }

            maxNetworkThroughputBytesPerSecond = (long)Math.Round(throughputMiB * 1024d * 1024d);
        }

        var custodyPathRaw = ChainOfCustodyLogPathTextBox.Text?.Trim();
        if (!string.IsNullOrWhiteSpace(custodyPathRaw))
        {
            try
            {
                chainOfCustodyLogPath = Path.GetFullPath(custodyPathRaw);
            }
            catch (Exception ex)
            {
                errorMessage = $"Chain-of-custody log path is invalid: {ex.Message}";
                return false;
            }
        }

        return true;
    }

    private static bool TryParsePositiveInt(string? value, int min, int max, int fallback, out int parsed)
    {
        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var raw))
        {
            parsed = fallback;
            return false;
        }

        parsed = Math.Clamp(raw, min, max);
        return raw == parsed;
    }

    private static bool TryParseOptionalUlong(string? value, out ulong? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        if (!ulong.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
        {
            return false;
        }

        parsed = numeric;
        return true;
    }

    private static bool TryParseOptionalUInt(string? value, out uint? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        if (!uint.TryParse(value.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
        {
            return false;
        }

        parsed = numeric;
        return true;
    }

    private bool TryBuildRaidManualOverride(
        out EngineRaidManualOverride? manualOverride,
        out string errorMessage)
    {
        manualOverride = null;
        errorMessage = string.Empty;
        if (RaidManualOverrideCheckBox.IsChecked != true)
        {
            return true;
        }

        var hasLevel = !string.IsNullOrWhiteSpace(RaidLevelOverrideTextBox.Text);
        var hasStripe = !string.IsNullOrWhiteSpace(RaidStripeSizeTextBox.Text);
        var hasOffset = !string.IsNullOrWhiteSpace(RaidDataOffsetTextBox.Text);
        var hasParity = !string.IsNullOrWhiteSpace(RaidParityRotationTextBox.Text);
        var hasDiskOrder = !string.IsNullOrWhiteSpace(RaidDiskOrderTextBox.Text);

        if (!hasLevel && !hasStripe && !hasOffset && !hasParity && !hasDiskOrder)
        {
            errorMessage = "RAID override is enabled but no override fields were provided.";
            return false;
        }

        uint stripeSizeBytes = 0;
        if (hasStripe)
        {
            if (!TryParseOptionalUInt(RaidStripeSizeTextBox.Text, out var parsedStripe) || !parsedStripe.HasValue)
            {
                errorMessage = "RAID stripe size must be an unsigned integer.";
                return false;
            }
            stripeSizeBytes = parsedStripe.Value;
        }

        ulong dataOffsetBytes = 0;
        if (hasOffset)
        {
            if (!TryParseOptionalUlong(RaidDataOffsetTextBox.Text, out var parsedOffset) || !parsedOffset.HasValue)
            {
                errorMessage = "RAID data offset must be an unsigned integer.";
                return false;
            }
            dataOffsetBytes = parsedOffset.Value;
        }

        var levelValue = hasLevel ? NormalizeRaidLevel(RaidLevelOverrideTextBox.Text) : null;
        if (hasLevel && levelValue is null)
        {
            errorMessage = "RAID level must be one of: raid0, raid1, raid4, raid5, raid6, raid10.";
            return false;
        }

        var parityValue = hasParity ? NormalizeRaidParityRotation(RaidParityRotationTextBox.Text) : null;
        if (hasParity && parityValue is null)
        {
            errorMessage = "RAID parity rotation must be either: left or right.";
            return false;
        }

        IReadOnlyList<uint>? diskOrder = null;
        if (hasDiskOrder)
        {
            var parsedDiskOrder = ParseRaidDiskOrder(RaidDiskOrderTextBox.Text);
            if (parsedDiskOrder is null)
            {
                errorMessage = "RAID disk order must be comma-separated unsigned integers (example: 0,1,2,3).";
                return false;
            }

            if (parsedDiskOrder.Count == 0)
            {
                errorMessage = "RAID disk order cannot be empty.";
                return false;
            }

            diskOrder = parsedDiskOrder;
        }

        manualOverride = new EngineRaidManualOverride(
            OverrideLevel: hasLevel,
            Level: levelValue,
            OverrideStripeSize: hasStripe,
            StripeSizeBytes: stripeSizeBytes,
            OverrideDataOffset: hasOffset,
            DataOffsetBytes: dataOffsetBytes,
            OverrideParityRotation: hasParity,
            ParityRotation: parityValue,
            DiskOrder: diskOrder);
        return true;
    }

    private bool TryParseRaidMemberSourcePaths(
        out IReadOnlyList<string> paths,
        out string errorMessage)
    {
        paths = Array.Empty<string>();
        errorMessage = string.Empty;

        var raw = RaidMemberSourcesTextBox.Text;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        var tokens = raw
            .Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(value => value.Trim())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();

        if (tokens.Count < 2)
        {
            errorMessage = "RAID member sources must include at least 2 paths.";
            return false;
        }

        var normalized = new List<string>(tokens.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var token in tokens)
        {
            try
            {
                var fullPath = Path.GetFullPath(token);
                if (!seen.Add(fullPath))
                {
                    continue;
                }

                normalized.Add(fullPath);
            }
            catch (Exception ex)
            {
                errorMessage = $"Invalid RAID member source path '{token}': {ex.Message}";
                return false;
            }
        }

        if (normalized.Count < 2)
        {
            errorMessage = "RAID member sources must resolve to at least 2 unique paths.";
            return false;
        }

        paths = normalized;
        return true;
    }

    private static RecoverySourceKind InferSourceKindFromPath(string sourcePath)
    {
        if (sourcePath.StartsWith(@"\\.\PHYSICALDRIVE", StringComparison.OrdinalIgnoreCase))
        {
            return RecoverySourceKind.PhysicalDisk;
        }

        if (sourcePath.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase))
        {
            return RecoverySourceKind.Volume;
        }

        return RecoverySourceKind.ImageFile;
    }

    private static string? NormalizeRaidLevel(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "raid0" => "RAID0",
            "raid1" => "RAID1",
            "raid4" => "RAID4",
            "raid5" => "RAID5",
            "raid6" => "RAID6",
            "raid10" => "RAID10",
            _ => null,
        };
    }

    private static string? NormalizeRaidParityRotation(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            "left" => "LeftSymmetric",
            "right" => "RightSymmetric",
            _ => null,
        };
    }

    private static IReadOnlyList<uint>? ParseRaidDiskOrder(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<uint>();
        }

        var segments = raw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var values = new List<uint>(segments.Length);
        foreach (var segment in segments)
        {
            if (!uint.TryParse(segment, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            {
                return null;
            }

            values.Add(parsed);
        }

        return values;
    }

    private static IReadOnlyList<uint>? ParseRaidMissingMembers(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<uint>();
        }

        var segments = raw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var values = new List<uint>(segments.Length);
        foreach (var segment in segments)
        {
            if (!uint.TryParse(segment, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
            {
                return null;
            }

            values.Add(parsed);
        }

        return values.Distinct().OrderBy(value => value).ToArray();
    }

    private sealed record RaidAssistantOverride(
        string Description,
        EngineRaidManualOverride Override);

    private sealed record RaidAssistantRankedResult(
        RaidAssistantOverride Suggestion,
        EngineRaidLayoutProbeResult Probe,
        EngineRaidDegradedAssessmentResult Degraded,
        int Score);

    private static IReadOnlyList<RaidAssistantOverride> BuildRaidReverseAssistantOverrides(
        EngineRaidLayoutMetadata metadata)
    {
        if (metadata.DiskOrder.Count < 2)
        {
            return Array.Empty<RaidAssistantOverride>();
        }

        var suggestions = new List<RaidAssistantOverride>();
        var reversed = metadata.DiskOrder.Reverse().ToArray();
        suggestions.Add(new RaidAssistantOverride(
            "reverse disk order",
            new EngineRaidManualOverride(
                OverrideLevel: true,
                Level: metadata.Level,
                OverrideStripeSize: true,
                StripeSizeBytes: metadata.StripeSizeBytes,
                OverrideDataOffset: true,
                DataOffsetBytes: metadata.DataOffsetBytes,
                OverrideParityRotation: true,
                ParityRotation: metadata.ParityRotation,
                DiskOrder: reversed)));

        var switchedParity = string.Equals(metadata.ParityRotation, "LeftSymmetric", StringComparison.OrdinalIgnoreCase)
            ? "RightSymmetric"
            : "LeftSymmetric";
        suggestions.Add(new RaidAssistantOverride(
            "flip parity rotation",
            new EngineRaidManualOverride(
                OverrideLevel: true,
                Level: metadata.Level,
                OverrideStripeSize: true,
                StripeSizeBytes: metadata.StripeSizeBytes,
                OverrideDataOffset: true,
                DataOffsetBytes: metadata.DataOffsetBytes,
                OverrideParityRotation: true,
                ParityRotation: switchedParity,
                DiskOrder: metadata.DiskOrder)));

        if (metadata.DiskOrder.Count >= 3)
        {
            var rotated = metadata.DiskOrder.Skip(1).Concat(metadata.DiskOrder.Take(1)).ToArray();
            suggestions.Add(new RaidAssistantOverride(
                "rotate disk order by 1 (degraded reconstruction hint)",
                new EngineRaidManualOverride(
                    OverrideLevel: true,
                    Level: metadata.Level,
                    OverrideStripeSize: true,
                    StripeSizeBytes: metadata.StripeSizeBytes,
                    OverrideDataOffset: true,
                    DataOffsetBytes: metadata.DataOffsetBytes,
                    OverrideParityRotation: true,
                    ParityRotation: metadata.ParityRotation,
                    DiskOrder: rotated)));
        }

        return suggestions;
    }

    private static IReadOnlyList<RaidAssistantRankedResult> RankRaidAssistantOverrides(
        ulong sessionId,
        IReadOnlyList<RaidAssistantOverride> suggestions,
        IReadOnlyList<uint> missingMembers)
    {
        var ranked = new List<RaidAssistantRankedResult>(suggestions.Count);
        foreach (var suggestion in suggestions)
        {
            var probe = NativeEngineProbe.ProbeRaidLayoutFromSession(sessionId, suggestion.Override);
            var degraded = probe.Success && probe.Metadata is not null
                ? NativeEngineProbe.AssessRaidDegradedLayout(probe.Metadata, missingMembers, sampleCount: 96)
                : new EngineRaidDegradedAssessmentResult(
                    EngineAvailable: probe.EngineAvailable,
                    Success: false,
                    Assessment: null,
                    Message: "Skipped degraded scoring due to probe failure.",
                    StatusCode: probe.StatusCode);
            var score = ComputeRaidAssistantScore(probe, degraded);
            ranked.Add(new RaidAssistantRankedResult(suggestion, probe, degraded, score));
        }

        return ranked
            .OrderByDescending(item => item.Score)
            .ThenBy(item => item.Suggestion.Description, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static int ComputeRaidAssistantScore(
        EngineRaidLayoutProbeResult probe,
        EngineRaidDegradedAssessmentResult degraded)
    {
        if (!probe.Success || probe.Metadata is null)
        {
            return -1000;
        }

        var score = (int)probe.Metadata.ConfidenceScore;
        if (!string.Equals(probe.Metadata.Level, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            score += 8;
        }

        if (!string.Equals(probe.Metadata.ParityRotation, "Unknown", StringComparison.OrdinalIgnoreCase))
        {
            score += 6;
        }

        if (degraded.Success && degraded.Assessment is not null)
        {
            score += degraded.Assessment.RecoverabilityPercent * 2;
            score -= degraded.Assessment.ConfidencePenalty;
        }
        else
        {
            score -= 24;
        }

        return score;
    }

    private static DateTime? ToUtcStartOfDay(DateTime? date)
    {
        if (!date.HasValue)
        {
            return null;
        }

        var local = DateTime.SpecifyKind(date.Value.Date, DateTimeKind.Local);
        return local.ToUniversalTime();
    }

    private static DateTime? ToUtcEndOfDay(DateTime? date)
    {
        if (!date.HasValue)
        {
            return null;
        }

        var local = DateTime.SpecifyKind(date.Value.Date.AddDays(1).AddTicks(-1), DateTimeKind.Local);
        return local.ToUniversalTime();
    }

    private int GetQuickScanMaxRecords()
    {
        if (!TryParsePositiveInt(
                QuickScanMaxRecordsTextBox.Text,
                min: 32,
                max: 4096,
                fallback: DefaultQuickScanMaxRecords,
                out var value))
        {
            QuickScanMaxRecordsTextBox.Text = value.ToString(CultureInfo.InvariantCulture);
        }

        return value;
    }

    private int GetCandidateCapacity()
    {
        if (!TryParsePositiveInt(
                CandidateCapacityTextBox.Text,
                min: 32,
                max: 4096,
                fallback: DefaultCandidateCapacity,
                out var value))
        {
            CandidateCapacityTextBox.Text = value.ToString(CultureInfo.InvariantCulture);
        }

        return value;
    }

    private ulong GetPreviewCapBytes()
    {
        if (!TryParsePositiveInt(
                PreviewCapMiBTextBox.Text,
                min: 1,
                max: 256,
                fallback: DefaultPreviewCapMiB,
                out var mib))
        {
            PreviewCapMiBTextBox.Text = mib.ToString(CultureInfo.InvariantCulture);
        }

        return checked((ulong)mib * 1024UL * 1024UL);
    }

    private int GetPreviewChunkBytes()
    {
        if (!TryParsePositiveInt(
                PreviewChunkKiBTextBox.Text,
                min: 64,
                max: 4096,
                fallback: DefaultPreviewChunkKiB,
                out var kib))
        {
            PreviewChunkKiBTextBox.Text = kib.ToString(CultureInfo.InvariantCulture);
        }

        return checked(kib * 1024);
    }

    private static string BuildCandidateSelectionKey(QuickScanCandidateRow row)
    {
        return BuildCandidateSelectionKey(row.RecordNumber, row.Name, row.OriginalPath);
    }

    private static string BuildCandidateSelectionKey(uint recordNumber, string? name, string? originalPath)
    {
        var normalizedName = string.IsNullOrWhiteSpace(name) ? "(unknown)" : name.Trim().ToLowerInvariant();
        var normalizedPath = string.IsNullOrWhiteSpace(originalPath) ? "(unresolved)" : originalPath.Trim().ToLowerInvariant();
        return $"{recordNumber.ToString(CultureInfo.InvariantCulture)}|{normalizedName}|{normalizedPath}";
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

        if (!string.Equals(_filterFileType, "All", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(row.FileType, _filterFileType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(_filterStatus, "All", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(row.CandidateStatusCode, _filterStatus, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(_filterEvidence, "All", StringComparison.OrdinalIgnoreCase)
            && !row.EvidenceSource.Contains(_filterEvidence, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(_filterConfidence, "All", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(row.ConfidenceTier, _filterConfidence, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var rowSize = row.DataSizeBytes ?? row.CarveLengthBytes ?? 0UL;
        if (_filterMinSizeBytes.HasValue && rowSize < _filterMinSizeBytes.Value)
        {
            return false;
        }

        if (_filterMaxSizeBytes.HasValue && rowSize > _filterMaxSizeBytes.Value)
        {
            return false;
        }

        var modifiedUtc = TryConvertFileTimeUtc(row.ModifiedFileTimeUtc);
        if (_filterModifiedFromUtc.HasValue
            && (!modifiedUtc.HasValue || modifiedUtc.Value < _filterModifiedFromUtc.Value))
        {
            return false;
        }

        if (_filterModifiedToUtc.HasValue
            && (!modifiedUtc.HasValue || modifiedUtc.Value > _filterModifiedToUtc.Value))
        {
            return false;
        }

        if (_filterDeletedFromUtc.HasValue || _filterDeletedToUtc.HasValue)
        {
            if (!row.Deleted)
            {
                return false;
            }

            var deletedProxyUtc = TryConvertFileTimeUtc(row.MftModifiedFileTimeUtc) ?? TryConvertFileTimeUtc(row.ModifiedFileTimeUtc);
            if (_filterDeletedFromUtc.HasValue
                && (!deletedProxyUtc.HasValue || deletedProxyUtc.Value < _filterDeletedFromUtc.Value))
            {
                return false;
            }

            if (_filterDeletedToUtc.HasValue
                && (!deletedProxyUtc.HasValue || deletedProxyUtc.Value > _filterDeletedToUtc.Value))
            {
                return false;
            }
        }

        if (string.IsNullOrWhiteSpace(_candidateSearchTerm))
        {
            return true;
        }

        return row.Name.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.OriginalPath.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.RecoveredPath.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.FileType.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.RecordNumber.ToString(CultureInfo.InvariantCulture).Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.DataSizeDisplay.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.ModifiedUtcDisplay.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.FileAttributesDisplay.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.CarveOffsetDisplay.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.CarveFormat.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.EvidenceSource.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.CandidateStatusCode.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase)
            || row.RecoveryDiagnostics.Contains(_candidateSearchTerm, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRecoverableCandidate(QuickScanCandidateRow row)
    {
        return !row.Directory
            && !row.IsGhostRecord
            && row.CandidateStatus != RecoveryCandidateStatus.Invalid;
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
            $"Visible {visible}/{total} | Selected {selected} | Deleted {deleted} | Recoverable {recoverable} | Clusters {_candidateClusterCount} | Deduped {_candidateDedupedCount}";
    }

    private void ClearPreviewPanel()
    {
        PreviewHeaderTextBlock.Text = "Select a candidate to preview metadata and recovered content.";
        PreviewSummaryTextBox.Text = "No candidate selected.";
        PreviewTextTextBox.Text = string.Empty;
        PreviewHexTextBox.Text = string.Empty;
        PreviewMetadataTextBox.Text = string.Empty;
        PreviewImageControl.Source = null;
    }

    private void UpdatePreviewPanel(QuickScanCandidateRow candidate)
    {
        PreviewHeaderTextBlock.Text = $"Preview: R{candidate.RecordNumber} {candidate.Name}";

        var summary = new StringBuilder();
        summary.AppendLine($"Record: {candidate.RecordNumber}");
        summary.AppendLine($"Name: {candidate.Name}");
        summary.AppendLine($"File type: {candidate.FileType}");
        summary.AppendLine($"Original path: {candidate.OriginalPath}");
        summary.AppendLine($"Recovered path: {(string.IsNullOrWhiteSpace(candidate.RecoveredPath) ? "(not yet recovered in this UI session)" : candidate.RecoveredPath)}");
        summary.AppendLine($"Evidence: {candidate.EvidenceSource}");
        summary.AppendLine($"Confidence: {candidate.ConfidenceTier}");
        summary.AppendLine($"Status: {candidate.CandidateStatusCode}");
        summary.AppendLine($"Cluster: {candidate.ClusterDisplay}");
        summary.AppendLine($"Deduplicated siblings: {candidate.DeduplicatedCount}");
        summary.AppendLine($"Diagnostics: {candidate.RecoveryDiagnostics}");
        PreviewSummaryTextBox.Text = summary.ToString();

        PreviewMetadataTextBox.Text = BuildPreviewMetadata(candidate);

        var resolvedPath = TryResolveRecoveredPreviewPath(candidate);
        if (resolvedPath is null)
        {
            PreviewTextTextBox.Text = "Recover this candidate first to preview content.";
            PreviewHexTextBox.Text = "Recover this candidate first to inspect hex bytes.";
            PreviewImageControl.Source = null;
            return;
        }

        if (IsTextLikeExtension(resolvedPath))
        {
            try
            {
                PreviewTextTextBox.Text = LoadTextPreview(resolvedPath, maxChars: 16_000);
            }
            catch (Exception ex)
            {
                PreviewTextTextBox.Text = $"Unable to read text preview: {ex.Message}";
            }
        }
        else
        {
            PreviewTextTextBox.Text = "Text preview not available for this file type.";
        }

        try
        {
            PreviewHexTextBox.Text = LoadHexPreview(resolvedPath, maxBytes: 4096);
        }
        catch (Exception ex)
        {
            PreviewHexTextBox.Text = $"Unable to render hex preview: {ex.Message}";
        }

        if (IsImageExtension(resolvedPath))
        {
            try
            {
                using var stream = File.OpenRead(resolvedPath);
                var image = new BitmapImage();
                image.BeginInit();
                image.CacheOption = BitmapCacheOption.OnLoad;
                image.StreamSource = stream;
                image.EndInit();
                image.Freeze();
                PreviewImageControl.Source = image;
            }
            catch
            {
                PreviewImageControl.Source = null;
            }
        }
        else
        {
            PreviewImageControl.Source = null;
        }
    }

    private string? TryResolveRecoveredPreviewPath(QuickScanCandidateRow candidate)
    {
        if (!string.IsNullOrWhiteSpace(candidate.RecoveredPath) && File.Exists(candidate.RecoveredPath))
        {
            return candidate.RecoveredPath;
        }

        if (string.IsNullOrWhiteSpace(DestinationPathTextBox.Text))
        {
            return null;
        }

        var destination = Path.GetFullPath(DestinationPathTextBox.Text);
        var candidatePath = Path.Combine(destination, "RecoveredFiles", BuildRecoveryRelativePath(candidate));
        if (File.Exists(candidatePath))
        {
            candidate.RecoveredPath = candidatePath;
            return candidatePath;
        }

        return null;
    }

    private static string LoadHexPreview(string path, int maxBytes)
    {
        var bytes = File.ReadAllBytes(path);
        var length = Math.Min(maxBytes, bytes.Length);
        if (length == 0)
        {
            return "(empty file)";
        }

        const int bytesPerLine = 16;
        var sb = new StringBuilder();
        sb.AppendLine($"Hex preview ({length} of {bytes.Length} bytes)");
        for (var offset = 0; offset < length; offset += bytesPerLine)
        {
            var count = Math.Min(bytesPerLine, length - offset);
            var hex = new StringBuilder();
            var ascii = new StringBuilder();
            for (var i = 0; i < bytesPerLine; i++)
            {
                if (i < count)
                {
                    var value = bytes[offset + i];
                    hex.Append(value.ToString("X2", CultureInfo.InvariantCulture)).Append(' ');
                    ascii.Append(value is >= 32 and <= 126 ? (char)value : '.');
                }
                else
                {
                    hex.Append("   ");
                    ascii.Append(' ');
                }
            }

            sb.Append(offset.ToString("X8", CultureInfo.InvariantCulture))
                .Append("  ")
                .Append(hex)
                .Append(" |")
                .Append(ascii)
                .AppendLine("|");
        }

        return sb.ToString();
    }

    private string BuildPreviewMetadata(QuickScanCandidateRow candidate)
    {
        var metadata = new StringBuilder();
        metadata.AppendLine($"Created FILETIME: {candidate.CreatedFileTimeUtc?.ToString(CultureInfo.InvariantCulture) ?? "-"}");
        metadata.AppendLine($"Modified FILETIME: {candidate.ModifiedFileTimeUtc?.ToString(CultureInfo.InvariantCulture) ?? "-"}");
        metadata.AppendLine($"MFT Modified FILETIME: {candidate.MftModifiedFileTimeUtc?.ToString(CultureInfo.InvariantCulture) ?? "-"}");
        metadata.AppendLine($"Accessed FILETIME: {candidate.AccessedFileTimeUtc?.ToString(CultureInfo.InvariantCulture) ?? "-"}");
        metadata.AppendLine($"Attributes: {candidate.FileAttributesDisplay}");
        metadata.AppendLine($"Size: {candidate.DataSizeDisplay}");
        metadata.AppendLine($"Carve format: {candidate.CarveFormat}");
        metadata.AppendLine($"Carve offset: {candidate.CarveOffsetDisplay}");
        metadata.AppendLine($"Confidence reason: {candidate.ConfidenceReason}");

        var resolved = TryResolveRecoveredPreviewPath(candidate);
        if (!string.IsNullOrWhiteSpace(resolved))
        {
            if (TryExtractPdfTitle(resolved, out var pdfTitle))
            {
                metadata.AppendLine($"PDF title: {pdfTitle}");
            }

            if (TryExtractOpenXmlTitle(resolved, out var openXmlTitle))
            {
                metadata.AppendLine($"Document title: {openXmlTitle}");
            }
        }

        return metadata.ToString();
    }

    private static string LoadTextPreview(string path, int maxChars)
    {
        using var stream = File.OpenRead(path);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var buffer = new char[maxChars];
        var read = reader.Read(buffer, 0, buffer.Length);
        var content = new string(buffer, 0, read);
        if (reader.Peek() >= 0)
        {
            content += $"{Environment.NewLine}... [truncated preview]";
        }

        return content;
    }

    private static bool IsTextLikeExtension(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".txt" or ".log" or ".csv" or ".json" or ".xml" or ".md" or ".ini" or ".yaml" or ".yml";
    }

    private static bool IsImageExtension(string path)
    {
        var ext = Path.GetExtension(path).ToLowerInvariant();
        return ext is ".jpg" or ".jpeg" or ".png" or ".bmp" or ".gif" or ".tif" or ".tiff" or ".webp";
    }

    private void PopulateCandidateFilterOptions()
    {
        var currentFileType = FilterFileTypeComboBox.SelectedItem?.ToString() ?? "All";
        var currentStatus = FilterStatusComboBox.SelectedItem?.ToString() ?? "All";
        var currentEvidence = FilterEvidenceComboBox.SelectedItem?.ToString() ?? "All";
        var currentConfidence = FilterConfidenceComboBox.SelectedItem?.ToString() ?? "All";

        var fileTypes = _quickScanCandidates
            .Select(candidate => candidate.FileType)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        fileTypes.Insert(0, "All");
        FilterFileTypeComboBox.ItemsSource = fileTypes;

        var statuses = _quickScanCandidates
            .Select(candidate => candidate.CandidateStatusCode)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        statuses.Insert(0, "All");
        FilterStatusComboBox.ItemsSource = statuses;

        var evidence = _quickScanCandidates
            .SelectMany(candidate => candidate.EvidenceSource
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        evidence.Insert(0, "All");
        FilterEvidenceComboBox.ItemsSource = evidence;

        var confidence = _quickScanCandidates
            .Select(candidate => candidate.ConfidenceTier)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();
        confidence.Insert(0, "All");
        FilterConfidenceComboBox.ItemsSource = confidence;

        FilterFileTypeComboBox.SelectedItem = fileTypes.Contains(currentFileType, StringComparer.OrdinalIgnoreCase) ? currentFileType : "All";
        FilterStatusComboBox.SelectedItem = statuses.Contains(currentStatus, StringComparer.OrdinalIgnoreCase) ? currentStatus : "All";
        FilterEvidenceComboBox.SelectedItem = evidence.Contains(currentEvidence, StringComparer.OrdinalIgnoreCase) ? currentEvidence : "All";
        FilterConfidenceComboBox.SelectedItem = confidence.Contains(currentConfidence, StringComparer.OrdinalIgnoreCase) ? currentConfidence : "All";
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
        string? originalPath,
        string evidenceSources)
    {
        if (directory || isGhostRecord)
        {
            return RecoveryCandidateStatus.Invalid;
        }

        if (IsCarveEvidence(evidenceSources))
        {
            return RecoveryCandidateStatus.Partial;
        }

        if (IsFatEvidence(evidenceSources))
        {
            return deleted ? RecoveryCandidateStatus.Partial : RecoveryCandidateStatus.Invalid;
        }

        if (IsExtEvidence(evidenceSources))
        {
            return deleted ? RecoveryCandidateStatus.Partial : RecoveryCandidateStatus.Invalid;
        }

        if (IsMetadataOnlyEvidence(evidenceSources))
        {
            return deleted ? RecoveryCandidateStatus.Partial : RecoveryCandidateStatus.Invalid;
        }

        if (!deleted)
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

    private static bool IsCarveEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source => string.Equals(source, "Carve", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsFatEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source =>
                string.Equals(source, "FAT", StringComparison.OrdinalIgnoreCase)
                || string.Equals(source, "FAT32", StringComparison.OrdinalIgnoreCase)
                || string.Equals(source, "exFAT", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsExtEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source =>
                string.Equals(source, "ext4", StringComparison.OrdinalIgnoreCase)
                || string.Equals(source, "ext3", StringComparison.OrdinalIgnoreCase)
                || string.Equals(source, "ext2", StringComparison.OrdinalIgnoreCase)
                || string.Equals(source, "ext", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsRefsEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source => string.Equals(source, "ReFS", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsXfsEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source => string.Equals(source, "XFS", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsUfsEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source => string.Equals(source, "UFS", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsApfsEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source => string.Equals(source, "APFS", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsHfsEvidence(string? evidenceSources)
    {
        if (string.IsNullOrWhiteSpace(evidenceSources))
        {
            return false;
        }

        return evidenceSources
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(source => string.Equals(source, "HFS+", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsMetadataOnlyEvidence(string? evidenceSources)
    {
        return IsRefsEvidence(evidenceSources)
            || IsXfsEvidence(evidenceSources)
            || IsUfsEvidence(evidenceSources)
            || IsApfsEvidence(evidenceSources)
            || IsHfsEvidence(evidenceSources);
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

        var persisted = await _sessionStore.GetQuickScanCandidatesAsync(latest.SessionId, GetQuickScanMaxRecords(), cancellationToken);
        if (persisted.Count == 0)
        {
            return;
        }

        _activeSessionId = latest.SessionId;
        _activeSessionSourceClass = latest.SourceClass;
        _activeSignaturePackSet = latest.SignaturePackSet;
        _activeCustodyHashChainRef = latest.CustodyHashChainRef;
        _lastRemoteExecutionStatus = RemoteExecutionStatus.NotRequested;
        _lastRemoteExecutionErrorCode = RemoteExecutionErrorCode.None;
        _lastRemoteExecutionMessage = null;
        _lastRemoteExecutionIntegrityHash = null;
        RenderQuickScanCandidates(persisted);
        AppendSessionMessage($"Loaded {persisted.Count} persisted quick-scan candidates from session {latest.SessionId:D}.");
    }

    private async void SessionMaintenanceButton_Click(object sender, RoutedEventArgs e)
    {
        await RunSessionStoreMaintenanceAsync(userInitiated: true, compactDatabase: true, CancellationToken.None);
    }

    private async void ResumeLatestSessionButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var sessions = await _sessionStore.GetRecentSessionsAsync(1, CancellationToken.None);
            var latest = sessions.FirstOrDefault();
            if (latest is null)
            {
                AppendSessionMessage("Resume skipped: no persisted sessions are available.");
                StatusTextBlock.Text = "No persisted session";
                return;
            }

            _activeSessionId = latest.SessionId;
            _activeSessionSourceClass = latest.SourceClass;
            _activeSignaturePackSet = latest.SignaturePackSet;
            _activeCustodyHashChainRef = latest.CustodyHashChainRef;
            _lastRemoteExecutionStatus = RemoteExecutionStatus.NotRequested;
            _lastRemoteExecutionErrorCode = RemoteExecutionErrorCode.None;
            _lastRemoteExecutionMessage = null;
            _lastRemoteExecutionIntegrityHash = null;
            DestinationPathTextBox.Text = latest.DestinationPath;
            ScanModeComboBox.SelectedItem = latest.ScanMode;

            var source = _sources.FirstOrDefault(item =>
                string.Equals(item.Id, latest.SourceId, StringComparison.OrdinalIgnoreCase));
            if (source is not null)
            {
                SourcesDataGrid.SelectedItem = source;
            }

            var candidates = await _sessionStore.GetQuickScanCandidatesAsync(
                latest.SessionId,
                GetQuickScanMaxRecords(),
                CancellationToken.None);
            RenderQuickScanCandidates(candidates);
            AppendSessionMessage(
                $"Resumed session {latest.SessionId:D} ({latest.Status}) with {candidates.Count} candidates.");
            StatusTextBlock.Text = "Latest session resumed";
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Resume latest session failed: {ex.Message}");
            StatusTextBlock.Text = "Resume latest session failed";
        }
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
        ApplyCandidateFilters(logActivity: true);
    }

    private void CandidateFilterValueChanged(object sender, RoutedEventArgs e)
    {
        ApplyCandidateFilters(logActivity: false);
    }

    private void ApplyCandidateFilters(bool logActivity)
    {
        _filterDeletedOnly = FilterDeletedCheckBox.IsChecked == true;
        _filterRecoverableOnly = FilterRecoverableCheckBox.IsChecked == true;
        _filterSelectedOnly = FilterSelectedCheckBox.IsChecked == true;
        _filterFileType = FilterFileTypeComboBox.SelectedItem?.ToString() ?? "All";
        _filterStatus = FilterStatusComboBox.SelectedItem?.ToString() ?? "All";
        _filterEvidence = FilterEvidenceComboBox.SelectedItem?.ToString() ?? "All";
        _filterConfidence = FilterConfidenceComboBox.SelectedItem?.ToString() ?? "All";
        _filterMinSizeBytes = TryParseOptionalUlong(FilterMinSizeBytesTextBox.Text, out var minBytes)
            ? minBytes
            : null;
        _filterMaxSizeBytes = TryParseOptionalUlong(FilterMaxSizeBytesTextBox.Text, out var maxBytes)
            ? maxBytes
            : null;
        _filterModifiedFromUtc = ToUtcStartOfDay(FilterModifiedFromDatePicker.SelectedDate);
        _filterModifiedToUtc = ToUtcEndOfDay(FilterModifiedToDatePicker.SelectedDate);
        _filterDeletedFromUtc = ToUtcStartOfDay(FilterDeletedFromDatePicker.SelectedDate);
        _filterDeletedToUtc = ToUtcEndOfDay(FilterDeletedToDatePicker.SelectedDate);
        RefreshCandidateView();
        if (logActivity)
        {
            AppendCandidateActivity("Candidate filters updated.");
        }
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
        FilterFileTypeComboBox.SelectedIndex = 0;
        FilterStatusComboBox.SelectedIndex = 0;
        FilterEvidenceComboBox.SelectedIndex = 0;
        FilterConfidenceComboBox.SelectedIndex = 0;
        FilterMinSizeBytesTextBox.Text = string.Empty;
        FilterMaxSizeBytesTextBox.Text = string.Empty;
        FilterModifiedFromDatePicker.SelectedDate = null;
        FilterModifiedToDatePicker.SelectedDate = null;
        FilterDeletedFromDatePicker.SelectedDate = null;
        FilterDeletedToDatePicker.SelectedDate = null;
        CandidateSearchTextBox.Text = string.Empty;
        _filterDeletedOnly = false;
        _filterRecoverableOnly = false;
        _filterSelectedOnly = false;
        _filterFileType = "All";
        _filterStatus = "All";
        _filterEvidence = "All";
        _filterConfidence = "All";
        _filterMinSizeBytes = null;
        _filterMaxSizeBytes = null;
        _filterModifiedFromUtc = null;
        _filterModifiedToUtc = null;
        _filterDeletedFromUtc = null;
        _filterDeletedToUtc = null;
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

    private void QuickScanCandidatesDataGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (QuickScanCandidatesDataGrid.SelectedItem is not QuickScanCandidateRow candidate)
        {
            ClearPreviewPanel();
            return;
        }

        UpdatePreviewPanel(candidate);
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

    private bool ShowOperationWizard(
        string title,
        IReadOnlyList<string> checklistSteps,
        string summary)
    {
        var builder = new StringBuilder();
        builder.AppendLine(summary);
        builder.AppendLine();
        builder.AppendLine("Checklist:");
        for (var index = 0; index < checklistSteps.Count; index++)
        {
            builder.AppendLine($"{index + 1}. {checklistSteps[index]}");
        }
        builder.AppendLine();
        builder.AppendLine("Continue?");

        var result = System.Windows.MessageBox.Show(
            builder.ToString(),
            title,
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);
        return result == MessageBoxResult.Yes;
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

            if (!ShowOperationWizard(
                    "Export Wizard",
                    new[]
                    {
                        "Review selected candidates and active filters.",
                        "Confirm destination is on a separate volume from source.",
                        "Generate JSON and CSV export manifests for this session."
                    },
                    $"Export {selected.Length} selected candidate(s) to {destination}."))
            {
                AppendSessionMessage("Export canceled in wizard confirmation.");
                AppendCandidateActivity("Export canceled in wizard.");
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
                    file_type = candidate.FileType,
                    original_path = candidate.OriginalPath,
                    recovered_path = candidate.RecoveredPath,
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
                    confidence_score = candidate.ConfidenceScore,
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
        var directoryRecovered = 0;
        var directoryPartial = 0;
        var directoryFailed = 0;
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

            if (!ConfirmImageFirstRecommendation(_selectedSource, "recovery"))
            {
                StatusTextBlock.Text = "Recovery canceled (image-first recommended)";
                AppendCandidateActivity("Recovery canceled (image-first recommended).");
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

            if (!ShowOperationWizard(
                    "Recovery Wizard",
                    new[]
                    {
                        "Verify destination is not the same source disk/volume.",
                        "Review recoverable selection and candidate status.",
                        "Proceed with read-only source recovery and write results to destination."
                    },
                    $"Recover {selected.Length} selected candidate(s) to {destination}."))
            {
                AppendSessionMessage("Recovery canceled in wizard confirmation.");
                AppendCandidateActivity("Recovery canceled in wizard.");
                return;
            }

            recoveryRoot = Path.Combine(destination, "RecoveredFiles");
            Directory.CreateDirectory(recoveryRoot);

            var recoveryQueue = BuildRecoveryWorklist(
                selected,
                _quickScanCandidates.ToArray(),
                out var directorySelections);

            if (recoveryQueue.Count == 0)
            {
                foreach (var directorySelection in directorySelections)
                {
                    var directory = directorySelection.Directory;
                    directory.CandidateStatus = RecoveryCandidateStatus.Invalid;
                    directory.LastRecoveryStatusCode = -410;
                    directory.LastRecoveryDiagnosticsFlags = null;
                    directory.LastRecoveredBytes = 0;
                    directory.LastRecoveryPartial = null;
                    directory.RecoveryDiagnostics = "No recoverable child files were found under the selected directory.";
                    directoryFailed++;
                    failed++;
                    await PersistCandidateRecoveryDiagnosticsAsync(directory, operationToken);
                }

                RefreshCandidateView();
                AppendSessionMessage("Recovery skipped: selected items did not contain recoverable file candidates.");
                AppendCandidateActivity("Recovery skipped: no recoverable file candidates.");
                return;
            }

            if (_activeSessionId.HasValue)
            {
                await _sessionStore.UpdateStatusAsync(
                    _activeSessionId.Value,
                    "recovering",
                    $"Recovering {recoveryQueue.Count} file candidate(s) from {selected.Length} selected item(s).",
                    operationToken);
            }

            foreach (var candidate in recoveryQueue)
            {
                operationToken.ThrowIfCancellationRequested();

                if (IsCarveEvidence(candidate.EvidenceSource))
                {
                    var carveRelativePath = BuildRecoveryRelativePath(candidate);
                    var carveTargetPath = Path.Combine(recoveryRoot, carveRelativePath);
                    var carveTargetDirectory = Path.GetDirectoryName(carveTargetPath);
                    if (!string.IsNullOrWhiteSpace(carveTargetDirectory))
                    {
                        Directory.CreateDirectory(carveTargetDirectory);
                    }

                    var carveResult = RecoverCarvedCandidateToFile(
                        sourcePath,
                        _selectedSource.Kind,
                        candidate,
                        carveTargetPath,
                        operationToken);

                    if (carveResult.Success)
                    {
                        var finalCarvePath = carveTargetPath;
                        var renameSummary = TryApplyCarveMetadataRename(finalCarvePath, candidate, out var renamedPath);
                        if (!string.IsNullOrWhiteSpace(renamedPath))
                        {
                            finalCarvePath = renamedPath;
                        }

                        var metadataSummary = TryApplyRecoveredFileMetadata(finalCarvePath, candidate);

                        if (carveResult.Partial)
                        {
                            candidate.CandidateStatus = RecoveryCandidateStatus.Partial;
                            partial++;
                        }
                        else
                        {
                            candidate.CandidateStatus = RecoveryCandidateStatus.Full;
                            recovered++;
                        }

                        candidate.LastRecoveryStatusCode = carveResult.StatusCode;
                        candidate.LastRecoveryDiagnosticsFlags = carveResult.DiagnosticsFlags;
                        candidate.LastRecoveredBytes = carveResult.BytesWritten;
                        candidate.LastRecoveryPartial = carveResult.Partial;
                        candidate.RecoveryDiagnostics = CombineRecoveryDiagnostics(
                            carveResult.DiagnosticsSummary,
                            renameSummary,
                            metadataSummary);
                        candidate.RecoveredPath = finalCarvePath;
                        candidate.IsSelected = false;
                        AppendSessionMessage(
                            $"Recovered carve candidate {candidate.Name} to {finalCarvePath} ({(carveResult.Partial ? "partial" : "full")}, {carveResult.BytesWritten} bytes). Diagnostics: {candidate.RecoveryDiagnostics}");
                    }
                    else
                    {
                        candidate.CandidateStatus = MapRecoveryFailureStatus(carveResult.StatusCode);
                        candidate.LastRecoveryStatusCode = carveResult.StatusCode;
                        candidate.LastRecoveryDiagnosticsFlags = carveResult.DiagnosticsFlags;
                        candidate.LastRecoveredBytes = carveResult.BytesWritten;
                        candidate.LastRecoveryPartial = null;
                        candidate.RecoveryDiagnostics = carveResult.DiagnosticsSummary;
                        failed++;
                        AppendSessionMessage(
                            $"Carve recovery failed for {candidate.Name}: {carveResult.Message} (status {carveResult.StatusCode}).");
                    }

                    await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                    continue;
                }

                if (IsFatEvidence(candidate.EvidenceSource))
                {
                    if (!uint.TryParse(candidate.ParentRecord, NumberStyles.Integer, CultureInfo.InvariantCulture, out var startCluster)
                        || startCluster < 2)
                    {
                        candidate.CandidateStatus = RecoveryCandidateStatus.Invalid;
                        candidate.LastRecoveryStatusCode = 75;
                        candidate.LastRecoveryDiagnosticsFlags = null;
                        candidate.LastRecoveredBytes = 0;
                        candidate.LastRecoveryPartial = null;
                        candidate.RecoveryDiagnostics = "FAT/exFAT candidate metadata is missing a valid start cluster.";
                        failed++;
                        AppendSessionMessage(
                            $"Recovery failed for FAT/exFAT candidate R{candidate.RecordNumber}: invalid start cluster metadata.");
                        await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                        continue;
                    }

                    var fatRelativePath = BuildRecoveryRelativePath(candidate);
                    var fatTargetPath = Path.Combine(recoveryRoot, fatRelativePath);
                    var fatTargetDirectory = Path.GetDirectoryName(fatTargetPath);
                    if (!string.IsNullOrWhiteSpace(fatTargetDirectory))
                    {
                        Directory.CreateDirectory(fatTargetDirectory);
                    }

                    var fatResult = NativeEngineProbe.RecoverFatCandidateToFile(
                        sourcePath,
                        _selectedSource.Kind,
                        startCluster,
                        candidate.DataSizeBytes ?? 0,
                        fatTargetPath);

                    if (fatResult.Success)
                    {
                        var metadataSummary = TryApplyRecoveredFileMetadata(fatTargetPath, candidate);

                        if (fatResult.Partial)
                        {
                            candidate.CandidateStatus = RecoveryCandidateStatus.Partial;
                            partial++;
                        }
                        else
                        {
                            candidate.CandidateStatus = RecoveryCandidateStatus.Full;
                            recovered++;
                        }

                        candidate.LastRecoveryStatusCode = fatResult.StatusCode;
                        candidate.LastRecoveryDiagnosticsFlags = fatResult.DiagnosticsFlags;
                        candidate.LastRecoveredBytes = fatResult.BytesWritten;
                        candidate.LastRecoveryPartial = fatResult.Partial;
                        candidate.RecoveryDiagnostics = CombineRecoveryDiagnostics(fatResult.DiagnosticsSummary, metadataSummary);
                        candidate.RecoveredPath = fatTargetPath;
                        candidate.IsSelected = false;
                        AppendSessionMessage(
                            $"Recovered FAT/exFAT candidate R{candidate.RecordNumber} to {fatTargetPath} ({(fatResult.Partial ? "partial" : "full")}, {fatResult.BytesWritten} bytes). Diagnostics: {candidate.RecoveryDiagnostics}");
                    }
                    else
                    {
                        candidate.CandidateStatus = MapRecoveryFailureStatus(fatResult.StatusCode);
                        candidate.LastRecoveryStatusCode = fatResult.StatusCode;
                        candidate.LastRecoveryDiagnosticsFlags = fatResult.DiagnosticsFlags;
                        candidate.LastRecoveredBytes = fatResult.BytesWritten;
                        candidate.LastRecoveryPartial = null;
                        candidate.RecoveryDiagnostics = fatResult.DiagnosticsSummary;
                        failed++;
                        AppendSessionMessage(
                            $"FAT/exFAT recovery failed for R{candidate.RecordNumber}: {fatResult.Message} (status {fatResult.StatusCode}). Diagnostics: {fatResult.DiagnosticsSummary}");
                    }

                    await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                    continue;
                }

                if (IsExtEvidence(candidate.EvidenceSource))
                {
                    var extRelativePath = BuildRecoveryRelativePath(candidate);
                    var extTargetPath = Path.Combine(recoveryRoot, extRelativePath);
                    var extTargetDirectory = Path.GetDirectoryName(extTargetPath);
                    if (!string.IsNullOrWhiteSpace(extTargetDirectory))
                    {
                        Directory.CreateDirectory(extTargetDirectory);
                    }

                    _ = ulong.TryParse(candidate.ParentRecord, NumberStyles.Integer, CultureInfo.InvariantCulture, out var inodeNumber);
                    var extResult = NativeEngineProbe.RecoverExtCandidateToFile(
                        sourcePath,
                        _selectedSource.Kind,
                        inodeNumber,
                        extTargetPath);

                    if (extResult.Success)
                    {
                        candidate.CandidateStatus = extResult.Partial ? RecoveryCandidateStatus.Partial : RecoveryCandidateStatus.Full;
                        candidate.LastRecoveryStatusCode = extResult.StatusCode;
                        candidate.LastRecoveryDiagnosticsFlags = extResult.DiagnosticsFlags;
                        candidate.LastRecoveredBytes = extResult.BytesWritten;
                        candidate.LastRecoveryPartial = extResult.Partial;
                        candidate.RecoveryDiagnostics = extResult.DiagnosticsSummary;
                        candidate.RecoveredPath = extTargetPath;
                        candidate.IsSelected = false;
                        if (extResult.Partial)
                        {
                            partial++;
                        }
                        else
                        {
                            recovered++;
                        }
                        AppendSessionMessage(
                            $"Recovered ext candidate R{candidate.RecordNumber} to {extTargetPath} ({(extResult.Partial ? "partial" : "full")}, {extResult.BytesWritten} bytes). Diagnostics: {extResult.DiagnosticsSummary}");
                    }
                    else
                    {
                        candidate.CandidateStatus = MapRecoveryFailureStatus(extResult.StatusCode);
                        candidate.LastRecoveryStatusCode = extResult.StatusCode;
                        candidate.LastRecoveryDiagnosticsFlags = extResult.DiagnosticsFlags;
                        candidate.LastRecoveredBytes = extResult.BytesWritten;
                        candidate.LastRecoveryPartial = null;
                        candidate.RecoveryDiagnostics = extResult.DiagnosticsSummary;
                        failed++;
                        AppendSessionMessage(
                            $"ext recovery failed for R{candidate.RecordNumber}: {extResult.Message} (status {extResult.StatusCode}). Diagnostics: {extResult.DiagnosticsSummary}");
                    }

                    await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                    continue;
                }

                if (IsMetadataOnlyEvidence(candidate.EvidenceSource))
                {
                    if (!ulong.TryParse(candidate.ParentRecord, NumberStyles.Integer, CultureInfo.InvariantCulture, out var metadataId)
                        || metadataId == 0)
                    {
                        candidate.CandidateStatus = RecoveryCandidateStatus.Invalid;
                        candidate.LastRecoveryStatusCode = 170;
                        candidate.LastRecoveryDiagnosticsFlags = null;
                        candidate.LastRecoveredBytes = 0;
                        candidate.LastRecoveryPartial = null;
                        candidate.RecoveryDiagnostics = "Metadata candidate is missing a valid filesystem object identifier.";
                        failed++;
                        AppendSessionMessage(
                            $"Recovery failed for metadata candidate R{candidate.RecordNumber}: invalid object/inode identifier.");
                        await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                        continue;
                    }

                    var metadataContentRelativePath = BuildRecoveryRelativePath(candidate);
                    var metadataContentTargetPath = Path.Combine(recoveryRoot, metadataContentRelativePath);
                    var metadataContentTargetDirectory = Path.GetDirectoryName(metadataContentTargetPath);
                    if (!string.IsNullOrWhiteSpace(metadataContentTargetDirectory))
                    {
                        Directory.CreateDirectory(metadataContentTargetDirectory);
                    }

                    var metadataFsResult = RecoverMetadataFilesystemCandidateToFile(
                        sourcePath,
                        _selectedSource.Kind,
                        candidate,
                        metadataId,
                        metadataContentTargetPath);

                    if (metadataFsResult.Success)
                    {
                        var metadataSummary = TryApplyRecoveredFileMetadata(metadataContentTargetPath, candidate);
                        candidate.CandidateStatus = metadataFsResult.Partial ? RecoveryCandidateStatus.Partial : RecoveryCandidateStatus.Full;
                        candidate.LastRecoveryStatusCode = metadataFsResult.StatusCode;
                        candidate.LastRecoveryDiagnosticsFlags = metadataFsResult.DiagnosticsFlags;
                        candidate.LastRecoveredBytes = metadataFsResult.BytesWritten;
                        candidate.LastRecoveryPartial = metadataFsResult.Partial;
                        candidate.RecoveryDiagnostics = CombineRecoveryDiagnostics(metadataFsResult.DiagnosticsSummary, metadataSummary);
                        candidate.RecoveredPath = metadataContentTargetPath;
                        candidate.IsSelected = false;
                        if (metadataFsResult.Partial)
                        {
                            partial++;
                        }
                        else
                        {
                            recovered++;
                        }

                        AppendSessionMessage(
                            $"Recovered metadata candidate R{candidate.RecordNumber} to {metadataContentTargetPath} ({(metadataFsResult.Partial ? "partial" : "full")}, {metadataFsResult.BytesWritten} bytes). Diagnostics: {candidate.RecoveryDiagnostics}");
                        await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                        continue;
                    }

                    if (IsUnsupportedMetadataLayoutStatus(metadataFsResult.StatusCode))
                    {
                        var metadataRelativePath = BuildMetadataManifestRecoveryRelativePath(candidate);
                        var metadataTargetPath = Path.Combine(recoveryRoot, metadataRelativePath);
                        var metadataTargetDirectory = Path.GetDirectoryName(metadataTargetPath);
                        if (!string.IsNullOrWhiteSpace(metadataTargetDirectory))
                        {
                            Directory.CreateDirectory(metadataTargetDirectory);
                        }

                        var metadataManifestResult = ExportMetadataOnlyCandidateToFile(
                            candidate,
                            metadataTargetPath,
                            sourcePath,
                            _selectedSource.Kind);

                        if (metadataManifestResult.Success)
                        {
                            candidate.CandidateStatus = RecoveryCandidateStatus.Partial;
                            candidate.LastRecoveryStatusCode = metadataManifestResult.StatusCode;
                            candidate.LastRecoveryDiagnosticsFlags = metadataManifestResult.DiagnosticsFlags;
                            candidate.LastRecoveredBytes = metadataManifestResult.BytesWritten;
                            candidate.LastRecoveryPartial = true;
                            candidate.RecoveryDiagnostics = CombineRecoveryDiagnostics(
                                metadataManifestResult.DiagnosticsSummary,
                                $"Engine byte export unavailable: {metadataFsResult.Message}");
                            candidate.RecoveredPath = metadataTargetPath;
                            candidate.IsSelected = false;
                            partial++;
                            AppendSessionMessage(
                                $"Exported metadata fallback manifest for {candidate.Name} to {metadataTargetPath} ({metadataManifestResult.BytesWritten} bytes).");
                        }
                        else
                        {
                            candidate.CandidateStatus = RecoveryCandidateStatus.Invalid;
                            candidate.LastRecoveryStatusCode = metadataManifestResult.StatusCode;
                            candidate.LastRecoveryDiagnosticsFlags = metadataManifestResult.DiagnosticsFlags;
                            candidate.LastRecoveredBytes = metadataManifestResult.BytesWritten;
                            candidate.LastRecoveryPartial = null;
                            candidate.RecoveryDiagnostics = metadataManifestResult.DiagnosticsSummary;
                            failed++;
                            AppendSessionMessage(
                                $"Metadata export failed for R{candidate.RecordNumber}: {metadataManifestResult.Message} (status {metadataManifestResult.StatusCode}).");
                        }

                        await PersistCandidateRecoveryDiagnosticsAsync(candidate, operationToken);
                        continue;
                    }

                    candidate.CandidateStatus = RecoveryCandidateStatus.Invalid;
                    candidate.LastRecoveryStatusCode = metadataFsResult.StatusCode;
                    candidate.LastRecoveryDiagnosticsFlags = metadataFsResult.DiagnosticsFlags;
                    candidate.LastRecoveredBytes = metadataFsResult.BytesWritten;
                    candidate.LastRecoveryPartial = null;
                    candidate.RecoveryDiagnostics = metadataFsResult.DiagnosticsSummary;
                    failed++;
                    AppendSessionMessage(
                        $"Metadata recovery failed for R{candidate.RecordNumber}: {metadataFsResult.Message} (status {metadataFsResult.StatusCode}). Diagnostics: {metadataFsResult.DiagnosticsSummary}");
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
                    var metadataSummary = TryApplyRecoveredFileMetadata(targetPath, candidate);

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
                    candidate.RecoveryDiagnostics = CombineRecoveryDiagnostics(result.DiagnosticsSummary, metadataSummary);
                    candidate.RecoveredPath = targetPath;
                    candidate.IsSelected = false;
                    AppendSessionMessage(
                        $"Recovered R{candidate.RecordNumber} to {targetPath} ({(result.Partial ? "partial" : "full")}, {result.BytesWritten} bytes). Diagnostics: {candidate.RecoveryDiagnostics}");
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

            foreach (var directorySelection in directorySelections)
            {
                var directory = directorySelection.Directory;
                var children = directorySelection.Children;

                if (children.Count == 0)
                {
                    directory.CandidateStatus = RecoveryCandidateStatus.Invalid;
                    directory.LastRecoveryStatusCode = -410;
                    directory.LastRecoveryDiagnosticsFlags = null;
                    directory.LastRecoveredBytes = 0;
                    directory.LastRecoveryPartial = null;
                    directory.RecoveryDiagnostics = "No recoverable child files were found under the selected directory.";
                    directoryFailed++;
                    failed++;
                    AppendSessionMessage($"Directory R{directory.RecordNumber} skipped: no recoverable child files found.");
                    await PersistCandidateRecoveryDiagnosticsAsync(directory, operationToken);
                    continue;
                }

                var childFull = children.Count(candidate => candidate.CandidateStatus == RecoveryCandidateStatus.Full);
                var childPartial = children.Count(candidate => candidate.CandidateStatus == RecoveryCandidateStatus.Partial);
                var childFailed = children.Count - childFull - childPartial;
                var childBytes = children.Aggregate(
                    0UL,
                    (current, item) => current + (item.LastRecoveredBytes ?? 0));

                if (childFull == 0 && childPartial == 0)
                {
                    directory.CandidateStatus = RecoveryCandidateStatus.Invalid;
                    directory.LastRecoveryStatusCode = -412;
                    directory.LastRecoveryPartial = null;
                    directoryFailed++;
                    failed++;
                }
                else if (childFailed == 0 && childPartial == 0)
                {
                    directory.CandidateStatus = RecoveryCandidateStatus.Full;
                    directory.LastRecoveryStatusCode = 0;
                    directory.LastRecoveryPartial = false;
                    directoryRecovered++;
                }
                else
                {
                    directory.CandidateStatus = RecoveryCandidateStatus.Partial;
                    directory.LastRecoveryStatusCode = 0;
                    directory.LastRecoveryPartial = true;
                    directoryPartial++;
                }

                directory.LastRecoveryDiagnosticsFlags = null;
                directory.LastRecoveredBytes = childBytes;
                directory.RecoveryDiagnostics =
                    $"Directory expanded to {children.Count} child file(s): full={childFull}, partial={childPartial}, failed={childFailed}.";
                directory.IsSelected = false;

                AppendSessionMessage(
                    $"Directory R{directory.RecordNumber} expanded recovery: children={children.Count}, full={childFull}, partial={childPartial}, failed={childFailed}.");
                await PersistCandidateRecoveryDiagnosticsAsync(directory, operationToken);
            }

            RefreshCandidateView();
            StatusTextBlock.Text = "Recovery execution completed";

            if (_activeSessionId.HasValue)
            {
                await _sessionLogWriter.LogEventAsync(_activeSessionId.Value, "candidate_recovery", new
                {
                    selected_count = selected.Length,
                    expanded_file_count = recoveryQueue.Count,
                    recovered_full = recovered,
                    recovered_partial = partial,
                    failed,
                    overwritten_risk = overwrittenRisk,
                    recovered_directories_full = directoryRecovered,
                    recovered_directories_partial = directoryPartial,
                    failed_directories = directoryFailed,
                    destination_root = recoveryRoot,
                }, operationToken);

                await _sessionStore.UpdateStatusAsync(
                    _activeSessionId.Value,
                    "ready",
                    $"Recovery completed: files(full={recovered}, partial={partial}), directories(full={directoryRecovered}, partial={directoryPartial}), failed={failed}, overwritten-risk={overwrittenRisk}.",
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
                        expanded_file_count = recoveryQueue.Count,
                        recovered_full = recovered,
                        recovered_partial = partial,
                        failed,
                        overwritten_risk = overwrittenRisk,
                        recovered_directories_full = directoryRecovered,
                        recovered_directories_partial = directoryPartial,
                        failed_directories = directoryFailed,
                    }, operationToken);

                    AppendSessionMessage($"Recovery report written: {reportPath}");
                }
                catch (Exception ex)
                {
                    AppendSessionMessage($"Recovery report generation warning: {ex.Message}");
                }
            }

            AppendSessionMessage(
                $"Recovery summary: files(full={recovered}, partial={partial}), directories(full={directoryRecovered}, partial={directoryPartial}, failed={directoryFailed}), failed={failed}, overwritten-risk={overwrittenRisk}.");
            AppendCandidateActivity(
                $"Recovery summary files(full={recovered}, partial={partial}), dirs(full={directoryRecovered}, partial={directoryPartial}, failed={directoryFailed}), failed={failed}, overwritten-risk={overwrittenRisk}.");
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
                    $"Recovery canceled after progress files(full={recovered}, partial={partial}), directories(full={directoryRecovered}, partial={directoryPartial}, failed={directoryFailed}), failed={failed}, overwritten-risk={overwrittenRisk}, selected={selectedCount}.");
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
        builder.AppendLine($"- Source Class: `{_activeSessionSourceClass}`");
        builder.AppendLine($"- Signature Packs: `{_activeSignaturePackSet ?? "unknown"}`");
        builder.AppendLine($"- Custody Hash Chain Ref: `{_activeCustodyHashChainRef ?? "none"}`");
        builder.AppendLine($"- Remote Execution Status: `{_lastRemoteExecutionStatus}`");
        builder.AppendLine($"- Remote Execution Error: `{_lastRemoteExecutionErrorCode}`");
        builder.AppendLine($"- Remote Execution Message: `{_lastRemoteExecutionMessage ?? "n/a"}`");
        builder.AppendLine($"- Remote Execution Integrity: `{_lastRemoteExecutionIntegrityHash ?? "n/a"}`");
        builder.AppendLine($"- Destination Root: `{recoveryRoot}`");
        builder.AppendLine($"- Selected Candidates: `{selected.Count}`");
        builder.AppendLine($"- Clusters: `{selected.Select(candidate => candidate.ClusterId).Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase).Count()}`");
        builder.AppendLine($"- Deduplicated Candidates Suppressed: `{selected.Sum(candidate => candidate.DeduplicatedCount)}`");
        builder.AppendLine($"- Recovered Full: `{recovered}`");
        builder.AppendLine($"- Recovered Partial: `{partial}`");
        builder.AppendLine($"- Failed: `{failed}`");
        builder.AppendLine($"- Overwritten Risk: `{overwrittenRisk}`");
        builder.AppendLine();
        builder.AppendLine("## Candidate Details");
        builder.AppendLine();
        builder.AppendLine("| Cluster | Dedupe | Evidence | Record | Name | Type | Original Path | Recovered Path | Data Size | Modified UTC | Attr | Confidence | Score | Status | Recover Code | Diag Flags | Recovered Bytes | Partial | Diagnostics |");
        builder.AppendLine("|---|---:|---|---|---|---|---|---|---:|---|---|---|---:|---|---:|---:|---:|---|---|");

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
            var dedupe = candidate.DeduplicatedCount > 0
                ? candidate.DeduplicatedCount.ToString(CultureInfo.InvariantCulture)
                : "-";

            builder.AppendLine(
                $"| {EscapeMarkdownCell(candidate.ClusterDisplay)} | {dedupe} | {EscapeMarkdownCell(candidate.EvidenceSource)} | {candidate.RecordNumber} | {EscapeMarkdownCell(candidate.Name)} | {EscapeMarkdownCell(candidate.FileType)} | {EscapeMarkdownCell(candidate.OriginalPath)} | {EscapeMarkdownCell(candidate.RecoveredPath)} | {dataSize} | {modifiedUtc} | {fileAttributes} | {EscapeMarkdownCell(candidate.ConfidenceTier)} | {candidate.ConfidenceScoreDisplay} | {EscapeMarkdownCell(candidate.CandidateStatus.ToStorageCode())} | {recoverCode} | {diagnosticsFlags} | {recoveredBytes} | {partialValue} | {EscapeMarkdownCell(candidate.RecoveryDiagnostics)} |");
        }

        return builder.ToString();
    }

    private static string BuildSelectedCandidatesCsv(IReadOnlyList<QuickScanCandidateRow> selected)
    {
        var lines = new List<string>
        {
            "cluster_id,cluster_size,deduplicated_count,record_number,deleted,is_ghost_record,directory,non_resident_data,has_named_data_streams,compressed,sparse,encrypted,name,file_type,original_path,recovered_path,parent_record,data_size_bytes,allocated_size_bytes,file_attributes,created_filetime_utc,modified_filetime_utc,mft_modified_filetime_utc,accessed_filetime_utc,carve_offset_bytes,carve_length_bytes,carve_format,evidence_source,confidence_tier,confidence_score,status,recovery_status_code,recovery_diagnostics_flags,recovered_bytes,recovery_partial,recovery_diagnostics"
        };

        foreach (var candidate in selected)
        {
            lines.Add(string.Join(",",
                EscapeCsv(candidate.ClusterId),
                EscapeCsv(candidate.ClusterSize.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.DeduplicatedCount.ToString(CultureInfo.InvariantCulture)),
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
                EscapeCsv(candidate.FileType),
                EscapeCsv(candidate.OriginalPath),
                EscapeCsv(candidate.RecoveredPath),
                EscapeCsv(candidate.ParentRecord),
                EscapeCsv(candidate.DataSizeBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.AllocatedSizeBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.FileAttributesDisplay),
                EscapeCsv(candidate.CreatedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.ModifiedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.MftModifiedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.AccessedFileTimeUtc?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.CarveOffsetBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.CarveLengthBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.CarveFormat),
                EscapeCsv(candidate.EvidenceSource),
                EscapeCsv(candidate.ConfidenceTier),
                EscapeCsv(candidate.ConfidenceScoreDisplay),
                EscapeCsv(candidate.CandidateStatus.ToStorageCode()),
                EscapeCsv(candidate.LastRecoveryStatusCode?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.LastRecoveryDiagnosticsFlags?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.LastRecoveredBytes?.ToString(CultureInfo.InvariantCulture)),
                EscapeCsv(candidate.LastRecoveryPartial.HasValue ? (candidate.LastRecoveryPartial.Value ? "1" : "0") : null),
                EscapeCsv(candidate.RecoveryDiagnostics)));
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static EngineRecoverCandidateResult RecoverCarvedCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        QuickScanCandidateRow candidate,
        string outputPath,
        CancellationToken cancellationToken)
    {
        if (!candidate.CarveOffsetBytes.HasValue || !candidate.CarveLengthBytes.HasValue || candidate.CarveLengthBytes.Value == 0)
        {
            return new EngineRecoverCandidateResult(
                true,
                false,
                false,
                0,
                0,
                "No carve offset/length metadata available.",
                "Carve candidate is missing byte-range metadata.",
                -420);
        }

        var open = NativeEngineProbe.OpenSourceReadOnlySession(sourcePath, sourceKind);
        if (!open.EngineAvailable || !open.Opened)
        {
            return new EngineRecoverCandidateResult(
                open.EngineAvailable,
                false,
                false,
                0,
                0,
                "No additional diagnostics.",
                open.Message,
                open.StatusCode);
        }

        try
        {
            var outputDirectory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrWhiteSpace(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }
            using var stream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);

            var offset = candidate.CarveOffsetBytes.Value;
            var remaining = candidate.CarveLengthBytes.Value;
            ulong written = 0;
            var partial = false;
            var alignment = open.AlignmentBytes > 1 ? (ulong)open.AlignmentBytes : 1UL;

            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var chunkSize = (int)Math.Min(remaining, 1024 * 1024);
                var alignedOffset = (offset / alignment) * alignment;
                var prefix = checked((int)(offset - alignedOffset));
                var required = checked((ulong)prefix + (ulong)chunkSize);
                var alignedRequired = checked((int)(((required + alignment - 1) / alignment) * alignment));
                var buffer = new byte[alignedRequired];

                var read = NativeEngineProbe.ReadSourceSessionChunk(open.SessionId, alignedOffset, buffer);
                if (!read.Success)
                {
                    return new EngineRecoverCandidateResult(
                        true,
                        false,
                        false,
                        written,
                        0,
                        "Chunk read failed while exporting carved bytes.",
                        read.Message,
                        read.StatusCode);
                }

                if (read.BytesRead == 0)
                {
                    partial = true;
                    break;
                }

                if (read.BytesRead <= prefix)
                {
                    partial = true;
                    break;
                }

                var payloadBytes = (int)read.BytesRead - prefix;
                var toWrite = Math.Min(chunkSize, payloadBytes);
                stream.Write(buffer, prefix, toWrite);
                written += (ulong)toWrite;
                offset += (ulong)toWrite;
                remaining -= (ulong)toWrite;

                if (toWrite < chunkSize)
                {
                    partial = true;
                    break;
                }
            }

            return new EngineRecoverCandidateResult(
                true,
                true,
                partial,
                written,
                0,
                partial
                    ? "Carved byte range ended before requested length."
                    : "No additional diagnostics.",
                partial
                    ? "Carved candidate recovered with partial data."
                    : "Carved candidate recovered successfully.",
                0);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new EngineRecoverCandidateResult(
                true,
                false,
                false,
                0,
                0,
                "Write failed while exporting carved bytes.",
                ex.Message,
                -421);
        }
        finally
        {
            NativeEngineProbe.CloseSourceSession(open.SessionId);
        }
    }

    private static string BuildMetadataManifestRecoveryRelativePath(QuickScanCandidateRow candidate)
    {
        var baseRelativePath = BuildRecoveryRelativePath(candidate);
        return baseRelativePath + ".metadata.json";
    }

    private static bool IsUnsupportedMetadataLayoutStatus(int statusCode)
    {
        return statusCode == 170;
    }

    private static EngineRecoverCandidateResult RecoverMetadataFilesystemCandidateToFile(
        string sourcePath,
        RecoverySourceKind sourceKind,
        QuickScanCandidateRow candidate,
        ulong metadataId,
        string outputPath)
    {
        if (IsRefsEvidence(candidate.EvidenceSource))
        {
            return NativeEngineProbe.RecoverRefsCandidateToFile(sourcePath, sourceKind, metadataId, outputPath);
        }

        if (IsApfsEvidence(candidate.EvidenceSource))
        {
            return NativeEngineProbe.RecoverApfsCandidateToFile(sourcePath, sourceKind, metadataId, outputPath);
        }

        if (IsHfsEvidence(candidate.EvidenceSource))
        {
            return NativeEngineProbe.RecoverHfsCandidateToFile(sourcePath, sourceKind, metadataId, outputPath);
        }

        if (IsXfsEvidence(candidate.EvidenceSource))
        {
            return NativeEngineProbe.RecoverXfsCandidateToFile(sourcePath, sourceKind, metadataId, outputPath);
        }

        if (IsUfsEvidence(candidate.EvidenceSource))
        {
            return NativeEngineProbe.RecoverUfsCandidateToFile(sourcePath, sourceKind, metadataId, outputPath);
        }

        return new EngineRecoverCandidateResult(
            EngineAvailable: true,
            Success: false,
            Partial: false,
            BytesWritten: 0,
            DiagnosticsFlags: 0,
            DiagnosticsSummary: "Unsupported metadata evidence source.",
            Message: "No metadata filesystem recovery handler for this candidate.",
            StatusCode: 170);
    }

    private static EngineRecoverCandidateResult ExportMetadataOnlyCandidateToFile(
        QuickScanCandidateRow candidate,
        string outputPath,
        string sourcePath,
        RecoverySourceKind sourceKind)
    {
        try
        {
            var outputDirectory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrWhiteSpace(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }

            var payload = new
            {
                generated_utc = DateTimeOffset.UtcNow,
                source_path = sourcePath,
                source_kind = sourceKind.ToString(),
                evidence_source = candidate.EvidenceSource,
                record_number = candidate.RecordNumber,
                deleted = candidate.Deleted,
                directory = candidate.Directory,
                name = candidate.Name,
                original_path = candidate.OriginalPath,
                estimated_size_bytes = candidate.DataSizeBytes,
                confidence_tier = candidate.ConfidenceTier,
                confidence_score = candidate.ConfidenceScore,
                note =
                    "Metadata fallback export. Engine byte-export path reported unsupported layout for this candidate.",
            };
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true,
            });

            File.WriteAllText(outputPath, json, Encoding.UTF8);
            var bytesWritten = (ulong)new FileInfo(outputPath).Length;
            return new EngineRecoverCandidateResult(
                EngineAvailable: true,
                Success: true,
                Partial: true,
                BytesWritten: bytesWritten,
                DiagnosticsFlags: 0,
                DiagnosticsSummary:
                    "Metadata-manifest fallback export completed after unsupported byte-layout response.",
                Message: "Metadata manifest exported.",
                StatusCode: 0);
        }
        catch (Exception ex)
        {
            return new EngineRecoverCandidateResult(
                EngineAvailable: true,
                Success: false,
                Partial: false,
                BytesWritten: 0,
                DiagnosticsFlags: 0,
                DiagnosticsSummary: "Metadata-manifest export failed.",
                Message: ex.Message,
                StatusCode: -430);
        }
    }

    private static string CombineRecoveryDiagnostics(params string?[] diagnostics)
    {
        var parts = diagnostics
            .Where(part => !string.IsNullOrWhiteSpace(part))
            .Select(part => part!.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (parts.Length == 0)
        {
            return "No additional diagnostics.";
        }

        return string.Join(" ", parts);
    }

    private static string TryApplyRecoveredFileMetadata(string outputPath, QuickScanCandidateRow candidate)
    {
        if (!File.Exists(outputPath))
        {
            return "Export metadata skipped: output file not found.";
        }

        var notes = new List<string>();
        try
        {
            var createdUtc = TryConvertFileTimeUtc(candidate.CreatedFileTimeUtc);
            var modifiedUtc = TryConvertFileTimeUtc(candidate.ModifiedFileTimeUtc);
            var accessedUtc = TryConvertFileTimeUtc(candidate.AccessedFileTimeUtc);

            if (createdUtc.HasValue)
            {
                File.SetCreationTimeUtc(outputPath, createdUtc.Value);
            }
            if (modifiedUtc.HasValue)
            {
                File.SetLastWriteTimeUtc(outputPath, modifiedUtc.Value);
            }
            if (accessedUtc.HasValue)
            {
                File.SetLastAccessTimeUtc(outputPath, accessedUtc.Value);
            }

            if (createdUtc.HasValue || modifiedUtc.HasValue || accessedUtc.HasValue)
            {
                notes.Add("Preserved timestamps.");
            }
        }
        catch (Exception ex)
        {
            notes.Add($"Timestamp preservation skipped: {ex.Message}");
        }

        if (candidate.FileAttributes.HasValue)
        {
            try
            {
                var mapped = MapFileAttributesForExport(candidate.FileAttributes.Value);
                File.SetAttributes(outputPath, mapped);
                notes.Add($"Preserved attributes 0x{candidate.FileAttributes.Value:X8}.");
            }
            catch (Exception ex)
            {
                notes.Add($"Attribute preservation skipped: {ex.Message}");
            }
        }

        if (notes.Count == 0)
        {
            return "No export metadata available.";
        }

        return string.Join(" ", notes);
    }

    private static string TryApplyCarveMetadataRename(
        string outputPath,
        QuickScanCandidateRow candidate,
        out string? renamedPath)
    {
        renamedPath = null;
        if (!File.Exists(outputPath))
        {
            return "Metadata rename skipped: output file not found.";
        }

        if (!LooksGenericCarveName(candidate.Name))
        {
            return string.Empty;
        }

        if (!TryBuildCarveMetadataName(outputPath, candidate, out var baseName, out var reason))
        {
            return string.Empty;
        }

        var extension = Path.GetExtension(outputPath);
        var proposedName = $"{baseName}{extension}";
        var directory = Path.GetDirectoryName(outputPath);
        if (string.IsNullOrWhiteSpace(directory))
        {
            return string.Empty;
        }

        var targetPath = EnsureUniqueFilePath(Path.Combine(directory, proposedName));
        if (string.Equals(targetPath, outputPath, StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        File.Move(outputPath, targetPath);
        renamedPath = targetPath;

        var renamedFileName = Path.GetFileName(targetPath);
        candidate.Name = renamedFileName;
        candidate.OriginalPath = ReplaceLeafPathSegment(candidate.OriginalPath, renamedFileName);
        return $"Renamed using metadata heuristic ({reason}) to {renamedFileName}.";
    }

    private static bool TryBuildCarveMetadataName(
        string outputPath,
        QuickScanCandidateRow candidate,
        out string baseName,
        out string reason)
    {
        if (TryExtractOpenXmlTitle(outputPath, out var openXmlTitle))
        {
            baseName = "doc-" + SanitizeMetadataToken(openXmlTitle);
            reason = "document title metadata";
            return true;
        }

        if (TryExtractImageMetadataName(outputPath, out var imageName))
        {
            baseName = imageName;
            reason = "image metadata";
            return true;
        }

        if (TryExtractPdfTitle(outputPath, out var pdfTitle))
        {
            baseName = "pdf-" + SanitizeMetadataToken(pdfTitle);
            reason = "pdf title metadata";
            return true;
        }

        if (TryExtractMetadataTokenFromConfidenceReason(candidate.ConfidenceReason, out var confidenceToken))
        {
            baseName = "carve-" + confidenceToken;
            reason = "candidate metadata hint";
            return true;
        }

        baseName = string.Empty;
        reason = string.Empty;
        return false;
    }

    private static bool TryExtractOpenXmlTitle(string outputPath, out string title)
    {
        title = string.Empty;
        var extension = Path.GetExtension(outputPath);
        if (!string.Equals(extension, ".docx", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(extension, ".xlsx", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(extension, ".pptx", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var archive = ZipFile.OpenRead(outputPath);
            var core = archive.GetEntry("docProps/core.xml");
            if (core is null)
            {
                return false;
            }

            using var stream = core.Open();
            var document = XDocument.Load(stream, LoadOptions.None);
            XNamespace dcNs = "http://purl.org/dc/elements/1.1/";
            var node = document.Descendants(dcNs + "title").FirstOrDefault();
            if (node is null || string.IsNullOrWhiteSpace(node.Value))
            {
                return false;
            }

            title = node.Value.Trim();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryExtractImageMetadataName(string outputPath, out string name)
    {
        name = string.Empty;
        try
        {
            using var stream = File.OpenRead(outputPath);
            var decoder = BitmapDecoder.Create(
                stream,
                BitmapCreateOptions.IgnoreColorProfile | BitmapCreateOptions.PreservePixelFormat,
                BitmapCacheOption.None);
            if (decoder.Frames.Count == 0)
            {
                return false;
            }

            if (decoder.Frames[0].Metadata is not BitmapMetadata metadata)
            {
                return false;
            }

            var dateToken = TryNormalizeImageDateToken(metadata.DateTaken);
            var deviceToken = SanitizeMetadataToken(metadata.CameraModel ?? string.Empty);
            if (string.IsNullOrWhiteSpace(dateToken) && string.IsNullOrWhiteSpace(deviceToken))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(dateToken) && !string.IsNullOrWhiteSpace(deviceToken))
            {
                name = $"photo-{dateToken}-{deviceToken}";
                return true;
            }

            name = !string.IsNullOrWhiteSpace(dateToken)
                ? $"photo-{dateToken}"
                : $"photo-{deviceToken}";
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string TryNormalizeImageDateToken(string? dateTakenRaw)
    {
        if (string.IsNullOrWhiteSpace(dateTakenRaw))
        {
            return string.Empty;
        }

        if (DateTime.TryParseExact(
                dateTakenRaw.Trim(),
                "yyyy:MM:dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out var parsed))
        {
            return parsed.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        }

        if (DateTime.TryParse(dateTakenRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out parsed))
        {
            return parsed.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        }

        return string.Empty;
    }

    private static bool TryExtractPdfTitle(string outputPath, out string title)
    {
        title = string.Empty;
        if (!string.Equals(Path.GetExtension(outputPath), ".pdf", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            using var stream = File.OpenRead(outputPath);
            var length = (int)Math.Min(stream.Length, 512 * 1024);
            var buffer = new byte[length];
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read <= 0)
            {
                return false;
            }

            var content = Encoding.Latin1.GetString(buffer, 0, read);
            var match = PdfTitleRegex.Match(content);
            if (!match.Success)
            {
                return false;
            }

            title = match.Groups["title"].Value.Trim();
            return !string.IsNullOrWhiteSpace(title);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryExtractMetadataTokenFromConfidenceReason(string confidenceReason, out string token)
    {
        token = string.Empty;
        if (string.IsNullOrWhiteSpace(confidenceReason))
        {
            return false;
        }

        var match = Regex.Match(
            confidenceReason,
            "(?i)(title|subject|author|camera|device|model|date|datetime|taken)\\s*[:=]\\s*([^;|,]{3,96})",
            RegexOptions.CultureInvariant);
        if (!match.Success)
        {
            return false;
        }

        token = SanitizeMetadataToken(match.Groups[2].Value);
        return !string.IsNullOrWhiteSpace(token);
    }

    private static string SanitizeMetadataToken(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var invalid = Path.GetInvalidFileNameChars();
        var chars = value
            .Trim()
            .ToLowerInvariant()
            .Select(ch => invalid.Contains(ch) ? '-' : ch)
            .Select(ch => char.IsLetterOrDigit(ch) ? ch : '-')
            .ToArray();
        var sanitized = new string(chars);
        while (sanitized.Contains("--", StringComparison.Ordinal))
        {
            sanitized = sanitized.Replace("--", "-", StringComparison.Ordinal);
        }

        sanitized = sanitized.Trim('-');
        if (sanitized.Length > 64)
        {
            sanitized = sanitized[..64];
        }

        return sanitized;
    }

    private static bool LooksGenericCarveName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return true;
        }

        var normalized = name.Trim();
        return normalized.StartsWith("carve_", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("carve-", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("record-", StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith("file-record-", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalized, "(unknown)", StringComparison.OrdinalIgnoreCase);
    }

    private static string EnsureUniqueFilePath(string path)
    {
        if (!File.Exists(path))
        {
            return path;
        }

        var directory = Path.GetDirectoryName(path) ?? string.Empty;
        var baseName = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);

        for (var index = 1; index < 5000; index++)
        {
            var candidate = Path.Combine(directory, $"{baseName}-{index.ToString(CultureInfo.InvariantCulture)}{extension}");
            if (!File.Exists(candidate))
            {
                return candidate;
            }
        }

        return path;
    }

    private static string ReplaceLeafPathSegment(string originalPath, string newLeaf)
    {
        if (string.IsNullOrWhiteSpace(originalPath) || originalPath == "(unresolved)")
        {
            return newLeaf;
        }

        var parts = originalPath
            .Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries)
            .ToList();
        if (parts.Count == 0)
        {
            return newLeaf;
        }

        parts[^1] = SanitizePathSegment(newLeaf);
        return string.Join("\\", parts);
    }

    private static DateTime? TryConvertFileTimeUtc(ulong? fileTimeUtc)
    {
        if (!fileTimeUtc.HasValue || fileTimeUtc.Value == 0 || fileTimeUtc.Value > long.MaxValue)
        {
            return null;
        }

        try
        {
            return DateTime.FromFileTimeUtc((long)fileTimeUtc.Value);
        }
        catch
        {
            return null;
        }
    }

    private static FileAttributes MapFileAttributesForExport(uint fileAttributesRaw)
    {
        var raw = (FileAttributes)fileAttributesRaw;
        const FileAttributes allowed =
            FileAttributes.ReadOnly
            | FileAttributes.Hidden
            | FileAttributes.System
            | FileAttributes.Archive
            | FileAttributes.NotContentIndexed
            | FileAttributes.Temporary
            | FileAttributes.Offline;
        var mapped = raw & allowed;
        return mapped == 0 ? FileAttributes.Normal : mapped;
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

    private static uint BuildFatSyntheticRecordNumber(uint startCluster, int ordinal)
    {
        var mixed = unchecked(startCluster ^ ((uint)ordinal * 2654435761u));
        return unchecked(0xA000_0000u | (mixed & 0x1FFF_FFFFu));
    }

    private static uint BuildRefsSyntheticRecordNumber(ulong objectId, int ordinal)
    {
        var folded = (uint)(objectId ^ (objectId >> 32));
        var mixed = unchecked(folded ^ ((uint)ordinal * 2246822519u));
        return unchecked(0xB000_0000u | (mixed & 0x1FFF_FFFFu));
    }

    private static uint BuildExtSyntheticRecordNumber(ulong entryOffsetBytes, int ordinal)
    {
        var folded = (uint)(entryOffsetBytes ^ (entryOffsetBytes >> 32));
        var mixed = unchecked(folded ^ ((uint)ordinal * 3266489917u));
        return unchecked(0xD000_0000u | (mixed & 0x1FFF_FFFFu));
    }

    private static uint BuildXfsSyntheticRecordNumber(ulong inodeNumber, int ordinal)
    {
        var folded = (uint)(inodeNumber ^ (inodeNumber >> 32));
        var mixed = unchecked(folded ^ ((uint)ordinal * 2246822519u));
        return unchecked(0x9000_0000u | (mixed & 0x1FFF_FFFFu));
    }

    private static uint BuildUfsSyntheticRecordNumber(uint inodeNumber, int ordinal)
    {
        var mixed = unchecked(inodeNumber ^ ((uint)ordinal * 3266489917u));
        return unchecked(0x8000_0000u | (mixed & 0x1FFF_FFFFu));
    }

    private static uint BuildApfsSyntheticRecordNumber(ulong cnid, int ordinal)
    {
        var folded = (uint)(cnid ^ (cnid >> 32));
        var mixed = unchecked(folded ^ ((uint)ordinal * 668265263u));
        return unchecked(0xC000_0000u | (mixed & 0x1FFF_FFFFu));
    }

    private static uint BuildHfsSyntheticRecordNumber(uint cnid, int ordinal)
    {
        var mixed = unchecked(cnid ^ ((uint)ordinal * 2654435769u));
        return unchecked(0xE000_0000u | (mixed & 0x1FFF_FFFFu));
    }

    private static string NormalizeFatEvidenceLabel(string? filesystem)
    {
        if (string.IsNullOrWhiteSpace(filesystem))
        {
            return "FAT";
        }

        var normalized = filesystem.Trim();
        if (string.Equals(normalized, "fat32", StringComparison.OrdinalIgnoreCase))
        {
            return "FAT32";
        }
        if (string.Equals(normalized, "exfat", StringComparison.OrdinalIgnoreCase))
        {
            return "exFAT";
        }

        return "FAT";
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

    private static List<QuickScanCandidateRow> BuildRecoveryWorklist(
        IReadOnlyList<QuickScanCandidateRow> selected,
        IReadOnlyList<QuickScanCandidateRow> allCandidates,
        out List<DirectoryRecoverySelection> directorySelections)
    {
        directorySelections = new List<DirectoryRecoverySelection>();
        var queuedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var worklist = new List<QuickScanCandidateRow>();

        foreach (var candidate in selected)
        {
            if (candidate.Directory)
            {
                var children = FindRecoverableChildCandidates(candidate, allCandidates);
                directorySelections.Add(new DirectoryRecoverySelection(candidate, children));

                foreach (var child in children)
                {
                    var childKey = BuildCandidateSelectionKey(child.RecordNumber, child.Name, child.OriginalPath);
                    if (!queuedKeys.Add(childKey))
                    {
                        continue;
                    }

                    worklist.Add(child);
                }

                continue;
            }

            var candidateKey = BuildCandidateSelectionKey(candidate.RecordNumber, candidate.Name, candidate.OriginalPath);
            if (!queuedKeys.Add(candidateKey))
            {
                continue;
            }

            worklist.Add(candidate);
        }

        return worklist;
    }

    private static IReadOnlyList<QuickScanCandidateRow> FindRecoverableChildCandidates(
        QuickScanCandidateRow directoryCandidate,
        IReadOnlyList<QuickScanCandidateRow> allCandidates)
    {
        var directoryPath = NormalizeCandidatePathForMatch(directoryCandidate.OriginalPath);
        if (string.IsNullOrWhiteSpace(directoryPath)
            && !string.Equals(directoryCandidate.Name, "(unknown)", StringComparison.Ordinal))
        {
            directoryPath = NormalizeCandidatePathForMatch(directoryCandidate.Name);
        }

        if (string.IsNullOrWhiteSpace(directoryPath))
        {
            return Array.Empty<QuickScanCandidateRow>();
        }

        var prefix = directoryPath + "\\";
        var children = new List<QuickScanCandidateRow>();
        foreach (var candidate in allCandidates)
        {
            if (candidate.Directory || candidate.IsGhostRecord || !candidate.Deleted)
            {
                continue;
            }

            var candidatePath = NormalizeCandidatePathForMatch(candidate.OriginalPath);
            if (string.IsNullOrWhiteSpace(candidatePath))
            {
                continue;
            }

            if (candidatePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                children.Add(candidate);
            }
        }

        return children;
    }

    private static string? NormalizeCandidatePathForMatch(string? rawPath)
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

        normalized = normalized.Trim('\\');
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
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
        var line = $"[{DateTimeOffset.Now:HH:mm:ss}] {message}{Environment.NewLine}";
        SessionOutputTextBox.AppendText(line);
        SessionOutputTextBox.ScrollToEnd();
        DiagnosticsPageTextBox.AppendText(line);
        DiagnosticsPageTextBox.ScrollToEnd();
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

        var maxBytes = GetPreviewCapBytes();
        var chunkBytes = GetPreviewChunkBytes();
        var maxMiB = maxBytes / (1024UL * 1024UL);
        var chunkKiB = chunkBytes / 1024;
        AppendSessionMessage($"Starting preview read ({maxMiB} MiB cap, {chunkKiB} KiB chunks).");
        OperationProgressBar.Value = 0;
        ThroughputStatusTextBlock.Text = "Throughput: 0.00 MiB/s";

        var progress = new Progress<ReadPreviewProgress>(state =>
        {
            var percent = state.TargetBytes > 0
                ? Math.Min(100.0, (double)state.BytesRead * 100.0 / state.TargetBytes)
                : 0.0;
            OperationProgressBar.Value = percent;
            ThroughputStatusTextBlock.Text = $"Throughput: {state.ThroughputMiBPerSec:0.00} MiB/s";
            StatusTextBlock.Text =
                $"Preview read {state.BytesRead}/{state.TargetBytes} bytes at {state.ThroughputMiBPerSec:0.00} MiB/s";
        });

        ReadPreviewResult result;
        try
        {
            result = await _previewScanner.RunAsync(
                source,
                maxBytes: maxBytes,
                chunkSize: chunkBytes,
                cancellationToken: _previewReadCts.Token,
                progress: progress);
        }
        catch (Exception ex)
        {
            AppendSessionMessage($"Preview read error: {ex.Message}");
            StatusTextBlock.Text = "Preview read failed";
            ThroughputStatusTextBlock.Text = "Throughput: failed";
            OperationProgressBar.Value = 0;
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
            ThroughputStatusTextBlock.Text = "Throughput: canceled";
            OperationProgressBar.Value = 0;
            return;
        }

        StatusTextBlock.Text = result.Succeeded ? "Preview read completed" : "Preview read failed";
        ThroughputStatusTextBlock.Text = result.Succeeded
            ? "Throughput: complete"
            : "Throughput: failed";
        OperationProgressBar.Value = result.Succeeded ? 100 : 0;
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
        if (_runtimeEnvironmentProfile.IsWinPe)
        {
            _isElevated = true;
            ElevationWarningBorder.Visibility = Visibility.Collapsed;
            return;
        }

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

    private (bool ContinueSession, bool Unlocked) PrepareEncryptedSourceForSession(
        SourceCandidate source,
        string probePath)
    {
        var encryptedSources = NativeEngineProbe.ListEncryptedSources(probePath, source.Kind);
        if (encryptedSources.EngineAvailable && encryptedSources.Success)
        {
            var locked = encryptedSources.Sources.Where(item => item.Locked).ToArray();
            if (locked.Length == 0)
            {
                return (true, false);
            }

            var providers = string.Join(
                ", ",
                locked.Select(item => item.Provider).Distinct(StringComparer.OrdinalIgnoreCase));
            AppendSessionMessage(
                $"Encrypted source detected and locked (providers: {providers}). Explicit unlock required before scan.");

            var defaultProvider = locked.FirstOrDefault(item => !string.IsNullOrWhiteSpace(item.Provider))?.Provider ?? GuessEncryptedProvider(source);
            var request = PromptEncryptedUnlockRequest(source, defaultProvider);
            if (request is null)
            {
                _validationOutput.Add("Error: Encrypted source remains locked. Unlock flow was canceled.");
                AppendSessionMessage("Encrypted unlock flow canceled by operator.");
                return (false, false);
            }

            var unlockResult = NativeEngineProbe.UnlockEncryptedSource(
                probePath,
                source.Kind,
                request.Provider,
                request.CredentialKind,
                request.CredentialMaterial);
            AppendSessionMessage(
                $"Encrypted source unlock: {unlockResult.Message} (status {unlockResult.StatusCode}, provider={unlockResult.Provider}).");

            if (!unlockResult.EngineAvailable || !unlockResult.Success || !unlockResult.Unlocked)
            {
                _validationOutput.Add("Error: Encrypted source unlock failed. Verify provider and credential material.");
                return (false, false);
            }

            return (true, true);
        }

        if (LooksLikeEncryptedSource(source))
        {
            var warning = encryptedSources.EngineAvailable
                ? $"Encrypted source hint detected ({source.FileSystem ?? "unknown"}), but engine did not expose lock metadata ({encryptedSources.Message})."
                : $"Encrypted source hint detected ({source.FileSystem ?? "unknown"}), but encrypted-source API is unavailable ({encryptedSources.Message}).";
            _validationOutput.Add($"Warning: {warning}");
            AppendSessionMessage($"Encryption warning: {warning}");
        }

        return (true, false);
    }

    private EncryptedUnlockRequest? PromptEncryptedUnlockRequest(SourceCandidate source, string defaultProvider)
    {
        var dialog = new Window
        {
            Title = "Unlock Encrypted Source",
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ResizeMode = ResizeMode.NoResize,
            SizeToContent = SizeToContent.WidthAndHeight,
            MinWidth = 520,
            MinHeight = 280,
        };

        var root = new System.Windows.Controls.Grid
        {
            Margin = new System.Windows.Thickness(14),
        };
        root.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
        root.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
        root.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
        root.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
        root.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
        root.RowDefinitions.Add(new System.Windows.Controls.RowDefinition { Height = System.Windows.GridLength.Auto });
        root.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new System.Windows.GridLength(170) });
        root.ColumnDefinitions.Add(new System.Windows.Controls.ColumnDefinition { Width = new System.Windows.GridLength(320) });

        var sourceLabel = new System.Windows.Controls.TextBlock
        {
            Text = $"Source: {source.DisplayName}",
            FontWeight = System.Windows.FontWeights.SemiBold,
            Margin = new System.Windows.Thickness(0, 0, 0, 8),
            TextWrapping = System.Windows.TextWrapping.Wrap,
        };
        System.Windows.Controls.Grid.SetRow(sourceLabel, 0);
        System.Windows.Controls.Grid.SetColumnSpan(sourceLabel, 2);
        root.Children.Add(sourceLabel);

        var help = new System.Windows.Controls.TextBlock
        {
            Text = "Provide unlock material for encrypted source access. Credentials are used in-memory only and not written to logs or session database.",
            Margin = new System.Windows.Thickness(0, 0, 0, 10),
            TextWrapping = System.Windows.TextWrapping.Wrap,
        };
        System.Windows.Controls.Grid.SetRow(help, 1);
        System.Windows.Controls.Grid.SetColumnSpan(help, 2);
        root.Children.Add(help);

        var providerLabel = new System.Windows.Controls.TextBlock { Text = "Provider", VerticalAlignment = System.Windows.VerticalAlignment.Center };
        System.Windows.Controls.Grid.SetRow(providerLabel, 2);
        root.Children.Add(providerLabel);

        var providerBox = new System.Windows.Controls.ComboBox { Margin = new System.Windows.Thickness(8, 0, 0, 8) };
        providerBox.ItemsSource = new[] { "auto", "bitlocker", "filevault", "luks" };
        providerBox.SelectedItem = MapProviderForPrompt(defaultProvider);
        System.Windows.Controls.Grid.SetRow(providerBox, 2);
        System.Windows.Controls.Grid.SetColumn(providerBox, 1);
        root.Children.Add(providerBox);

        var kindLabel = new System.Windows.Controls.TextBlock { Text = "Credential Type", VerticalAlignment = System.Windows.VerticalAlignment.Center };
        System.Windows.Controls.Grid.SetRow(kindLabel, 3);
        root.Children.Add(kindLabel);

        var kindBox = new System.Windows.Controls.ComboBox { Margin = new System.Windows.Thickness(8, 0, 0, 8) };
        kindBox.ItemsSource = new[] { "password", "recovery_key", "key_file" };
        kindBox.SelectedItem = "password";
        System.Windows.Controls.Grid.SetRow(kindBox, 3);
        System.Windows.Controls.Grid.SetColumn(kindBox, 1);
        root.Children.Add(kindBox);

        var materialLabel = new System.Windows.Controls.TextBlock { Text = "Credential Material", VerticalAlignment = System.Windows.VerticalAlignment.Center };
        System.Windows.Controls.Grid.SetRow(materialLabel, 4);
        root.Children.Add(materialLabel);

        var materialBox = new System.Windows.Controls.PasswordBox { Margin = new System.Windows.Thickness(8, 0, 0, 12) };
        System.Windows.Controls.Grid.SetRow(materialBox, 4);
        System.Windows.Controls.Grid.SetColumn(materialBox, 1);
        root.Children.Add(materialBox);

        EncryptedUnlockRequest? request = null;

        var buttonPanel = new System.Windows.Controls.StackPanel
        {
            Orientation = System.Windows.Controls.Orientation.Horizontal,
            HorizontalAlignment = System.Windows.HorizontalAlignment.Right,
        };
        var cancelButton = new System.Windows.Controls.Button
        {
            Content = "Cancel",
            Width = 90,
            Margin = new System.Windows.Thickness(0, 0, 8, 0),
            IsCancel = true,
        };
        var unlockButton = new System.Windows.Controls.Button
        {
            Content = "Unlock",
            Width = 90,
            IsDefault = true,
        };
        unlockButton.Click += (_, _) =>
        {
            var provider = (providerBox.SelectedItem as string ?? "auto").Trim().ToLowerInvariant();
            var credentialKind = (kindBox.SelectedItem as string ?? "password").Trim().ToLowerInvariant();
            var credentialMaterial = materialBox.Password?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(credentialMaterial))
            {
                System.Windows.MessageBox.Show(
                    dialog,
                    "Credential material is required to unlock encrypted sources.",
                    "Unlock Required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            request = new EncryptedUnlockRequest(provider, credentialKind, credentialMaterial);
            dialog.DialogResult = true;
            dialog.Close();
        };

        buttonPanel.Children.Add(cancelButton);
        buttonPanel.Children.Add(unlockButton);
        System.Windows.Controls.Grid.SetRow(buttonPanel, 5);
        System.Windows.Controls.Grid.SetColumnSpan(buttonPanel, 2);
        root.Children.Add(buttonPanel);

        dialog.Content = root;
        var accepted = dialog.ShowDialog();
        return accepted == true ? request : null;
    }

    private static string MapProviderForPrompt(string provider)
    {
        return provider.Trim().ToLowerInvariant() switch
        {
            "bitlocker" => "bitlocker",
            "filevault" => "filevault",
            "luks" => "luks",
            _ => "auto",
        };
    }

    private static bool LooksLikeEncryptedSource(SourceCandidate source)
    {
        var hint = $"{source.FileSystem} {source.DisplayName}";
        return hint.Contains("bitlocker", StringComparison.OrdinalIgnoreCase)
            || hint.Contains("filevault", StringComparison.OrdinalIgnoreCase)
            || hint.Contains("apfs encrypted", StringComparison.OrdinalIgnoreCase)
            || hint.Contains("luks", StringComparison.OrdinalIgnoreCase)
            || hint.Contains("encrypted", StringComparison.OrdinalIgnoreCase);
    }

    private static string GuessEncryptedProvider(SourceCandidate source)
    {
        var hint = $"{source.FileSystem} {source.DisplayName}";
        if (hint.Contains("bitlocker", StringComparison.OrdinalIgnoreCase))
        {
            return "bitlocker";
        }

        if (hint.Contains("filevault", StringComparison.OrdinalIgnoreCase)
            || hint.Contains("apfs", StringComparison.OrdinalIgnoreCase))
        {
            return "filevault";
        }

        if (hint.Contains("luks", StringComparison.OrdinalIgnoreCase))
        {
            return "luks";
        }

        return "auto";
    }

    private static string ResolveSessionSourceClass(
        bool usingVirtualRaidSession,
        bool encryptedSourceUnlocked,
        bool remoteAgentRequested)
    {
        if (usingVirtualRaidSession)
        {
            return SessionSourceClass.AssembledRaid;
        }

        if (remoteAgentRequested)
        {
            return SessionSourceClass.RemoteAgent;
        }

        if (encryptedSourceUnlocked)
        {
            return SessionSourceClass.EncryptedUnlocked;
        }

        return SessionSourceClass.Local;
    }

    private static string? ResolveProbePath(SourceCandidate source)
    {
        if (IsVssSnapshotSource(source))
        {
            return !string.IsNullOrWhiteSpace(source.SourcePath)
                ? source.SourcePath
                : source.DevicePath;
        }

        return source.Kind switch
        {
            RecoverySourceKind.ImageFile => source.SourcePath,
            RecoverySourceKind.Volume => source.DevicePath,
            RecoverySourceKind.Partition => source.DevicePath,
            RecoverySourceKind.PhysicalDisk => source.DevicePath,
            _ => null,
        };
    }

    private async Task RefreshSmartHealthTelemetryAsync(CancellationToken cancellationToken)
    {
        try
        {
            var snapshot = await _storageHealthTelemetryService.GetSnapshotAsync(cancellationToken);
            _smartHealthOutput.Clear();

            foreach (var record in snapshot.Devices.OrderBy(item => item.DiskIndex ?? int.MaxValue))
            {
                _smartHealthOutput.Add(
                    $"Disk {record.DiskIndex?.ToString(CultureInfo.InvariantCulture) ?? "?"} | {record.HealthStatus} | PredictFailure={record.PredictFailure} | {record.Model}");
                if (!string.IsNullOrWhiteSpace(record.Warning))
                {
                    _validationOutput.Add($"Warning: {record.Warning}");
                }
            }

            foreach (var warning in snapshot.Warnings)
            {
                _smartHealthOutput.Add($"Warning: {warning}");
            }

            if (snapshot.Devices.Count == 0 && snapshot.Warnings.Count == 0)
            {
                _smartHealthOutput.Add("No SMART telemetry available.");
            }
        }
        catch (OperationCanceledException)
        {
            // no-op
        }
        catch (Exception ex)
        {
            _smartHealthOutput.Clear();
            _smartHealthOutput.Add($"SMART telemetry unavailable: {ex.Message}");
        }
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

