using FileRecovery.WindowsApp.Core.Models;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed partial class WindowsDeviceEnumerationService : IDeviceEnumerationService
{
    private readonly IStorageTopologyService _topologyService;

    public WindowsDeviceEnumerationService(IStorageTopologyService topologyService)
    {
        _topologyService = topologyService;
    }

    public Task<SourceEnumerationResult> EnumerateAsync(CancellationToken cancellationToken)
    {
        return Task.Run(() => EnumerateInternal(cancellationToken), cancellationToken);
    }

    public Task<SourceCandidate> BuildImageSourceAsync(string imagePath, CancellationToken cancellationToken)
    {
        return Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            var fullPath = Path.GetFullPath(imagePath);
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException("Image file not found.", fullPath);
            }

            var info = new FileInfo(fullPath);
            var volumeId = _topologyService.TryGetVolumeIdFromPath(fullPath);
            var mountPaths = volumeId is null
                ? []
                : _topologyService.GetMountPathsForVolumeId(volumeId);
            var imageFormat = DetectImageFormatLabel(fullPath);
            var partitionInfo = imageFormat is null
                ? "Image file source"
                : $"Image file source ({imageFormat})";
            var displayPrefix = imageFormat is null
                ? "Image"
                : $"{imageFormat} Image";
            var fileSystem = imageFormat is null ? null : $"VM image ({imageFormat})";

            return new SourceCandidate(
                Id: $"image-{info.Name}-{info.Length}",
                Kind: RecoverySourceKind.ImageFile,
                DisplayName: $"{displayPrefix}: {info.Name}",
                DevicePath: null,
                FileSystem: fileSystem,
                SizeBytes: info.Length,
                SectorSizeBytes: _topologyService.TryGetSectorSizeFromPath(fullPath),
                DiskIndex: _topologyService.TryGetDiskIndexFromPath(fullPath),
                VolumeIdentity: volumeId,
                SourcePath: fullPath,
                ReadOnlyEnforced: true,
                VolumeLabel: null,
                MountedPaths: string.Join(";", mountPaths),
                PartitionInfo: partitionInfo,
                IsNetworkSource: false,
                NetworkProtocol: null,
                NetworkEndpoint: null);
        }, cancellationToken);
    }

    public Task<SourceCandidate> BuildNetworkImageSourceAsync(
        NetworkSourceRequest request,
        CancellationToken cancellationToken)
    {
        return Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(request);

            if (string.IsNullOrWhiteSpace(request.SourcePath))
            {
                throw new ArgumentException("Network source path is required.", nameof(request));
            }

            var normalizedPath = NormalizeNetworkPath(request.SourcePath);
            if (!File.Exists(normalizedPath))
            {
                throw new FileNotFoundException("Network source image not found.", normalizedPath);
            }

            var info = new FileInfo(normalizedPath);
            var volumeId = _topologyService.TryGetVolumeIdFromPath(normalizedPath);
            var mountPaths = volumeId is null
                ? []
                : _topologyService.GetMountPathsForVolumeId(volumeId);
            var endpoint = ResolveNetworkEndpoint(normalizedPath, request.EndpointHint);
            var protocolLabel = request.Protocol switch
            {
                NetworkSourceProtocol.Smb => "SMB",
                NetworkSourceProtocol.Nfs => "NFS",
                _ => "Network",
            };
            var imageFormat = DetectImageFormatLabel(normalizedPath);
            var sourceLabel = imageFormat is null
                ? $"{protocolLabel} Image: {info.Name}"
                : $"{protocolLabel} {imageFormat} Image: {info.Name}";
            var partitionInfo = imageFormat is null
                ? $"{protocolLabel} mounted image source"
                : $"{protocolLabel} mounted image source ({imageFormat})";
            var fileSystem = imageFormat is null
                ? "Network image"
                : $"Network VM image ({imageFormat})";

            return new SourceCandidate(
                Id: $"network-{request.Protocol}-{info.Name}-{info.Length}",
                Kind: RecoverySourceKind.ImageFile,
                DisplayName: sourceLabel,
                DevicePath: null,
                FileSystem: fileSystem,
                SizeBytes: info.Length,
                SectorSizeBytes: _topologyService.TryGetSectorSizeFromPath(normalizedPath),
                DiskIndex: _topologyService.TryGetDiskIndexFromPath(normalizedPath),
                VolumeIdentity: volumeId,
                SourcePath: normalizedPath,
                ReadOnlyEnforced: true,
                VolumeLabel: null,
                MountedPaths: string.Join(";", mountPaths),
                PartitionInfo: partitionInfo,
                IsNetworkSource: true,
                NetworkProtocol: protocolLabel,
                NetworkEndpoint: endpoint);
        }, cancellationToken);
    }

    private SourceEnumerationResult EnumerateInternal(CancellationToken cancellationToken)
    {
        var sources = new List<SourceCandidate>();
        var warnings = new List<string>();

        Dictionary<string, DriveSnapshot> driveSnapshots;
        try
        {
            driveSnapshots = BuildDriveSnapshotMap(cancellationToken);
        }
        catch (Exception ex)
        {
            warnings.Add($"Drive metadata snapshot failed: {ex.Message}");
            driveSnapshots = new Dictionary<string, DriveSnapshot>(StringComparer.OrdinalIgnoreCase);
        }

        List<SourceCandidate> physicalDisks = [];
        try
        {
            physicalDisks.AddRange(EnumeratePhysicalDisks(cancellationToken));
        }
        catch (Exception ex)
        {
            warnings.Add($"Physical disk enumeration failed: {ex.Message}");
        }

        if (physicalDisks.Count == 0)
        {
            try
            {
                var fallbackPhysicalDisks = EnumeratePhysicalDisksFallback(cancellationToken).ToList();
                physicalDisks.AddRange(fallbackPhysicalDisks);
                if (fallbackPhysicalDisks.Count > 0)
                {
                    warnings.Add("Physical disk enumeration used Win32 fallback because WMI returned no results.");
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Physical disk fallback enumeration failed: {ex.Message}");
            }
        }

        sources.AddRange(physicalDisks);

        try
        {
            sources.AddRange(EnumerateLogicalVolumes(cancellationToken, driveSnapshots));
        }
        catch (Exception ex)
        {
            warnings.Add($"Volume enumeration failed: {ex.Message}");
        }

        List<SourceCandidate> partitions = [];
        try
        {
            partitions.AddRange(EnumeratePartitions(cancellationToken, driveSnapshots));
        }
        catch (Exception ex)
        {
            warnings.Add($"Partition enumeration failed: {ex.Message}");
        }

        if (partitions.Count == 0)
        {
            try
            {
                var setupApiFallbackPartitions = EnumeratePartitionsSetupApiFallback(cancellationToken, driveSnapshots).ToList();
                partitions.AddRange(setupApiFallbackPartitions);
                if (setupApiFallbackPartitions.Count > 0)
                {
                    warnings.Add("Partition enumeration used SetupAPI fallback (WMI returned no results).");
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Partition SetupAPI fallback enumeration failed: {ex.Message}");
            }
        }

        if (partitions.Count == 0)
        {
            try
            {
                var volumeFallbackPartitions = EnumeratePartitionsFromVolumesFallback(cancellationToken, driveSnapshots).ToList();
                partitions.AddRange(volumeFallbackPartitions);
                if (volumeFallbackPartitions.Count > 0)
                {
                    warnings.Add("Partition enumeration used mounted-volume fallback (WMI/SetupAPI returned no results).");
                }
            }
            catch (Exception ex)
            {
                warnings.Add($"Partition mounted-volume fallback enumeration failed: {ex.Message}");
            }
        }

        sources.AddRange(partitions);

        var ordered = sources
            .OrderBy(s => s.Kind)
            .ThenBy(s => s.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new SourceEnumerationResult(ordered, warnings);
    }

    private Dictionary<string, DriveSnapshot> BuildDriveSnapshotMap(CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, DriveSnapshot>(StringComparer.OrdinalIgnoreCase);

        foreach (var drive in DriveInfo.GetDrives())
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!drive.IsReady)
            {
                continue;
            }

            var rootPath = drive.RootDirectory.FullName;
            var rootKey = rootPath.TrimEnd('\\').ToUpperInvariant();
            var volumeId = _topologyService.TryGetVolumeIdFromPath(rootPath);
            var mountPaths = volumeId is null
                ? [rootPath]
                : _topologyService.GetMountPathsForVolumeId(volumeId);

            map[rootKey] = new DriveSnapshot(
                RootPath: rootPath,
                FileSystem: drive.DriveFormat,
                VolumeLabel: SafeVolumeLabel(drive),
                TotalSize: drive.TotalSize,
                SectorSizeBytes: _topologyService.TryGetSectorSizeFromPath(rootPath),
                DiskIndex: _topologyService.TryGetDiskIndexFromPath(rootPath),
                VolumeIdentity: volumeId,
                MountPaths: mountPaths);
        }

        return map;
    }

    private static string SafeVolumeLabel(DriveInfo drive)
    {
        try
        {
            return drive.VolumeLabel;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string NormalizeNetworkPath(string sourcePath)
    {
        var trimmed = sourcePath.Trim();
        if (trimmed.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return trimmed;
        }

        return Path.GetFullPath(trimmed);
    }

    private static string? ResolveNetworkEndpoint(string normalizedPath, string? endpointHint)
    {
        if (!string.IsNullOrWhiteSpace(endpointHint))
        {
            return endpointHint.Trim();
        }

        if (!normalizedPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return null;
        }

        var segments = normalizedPath
            .TrimStart('\\')
            .Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2)
        {
            return null;
        }

        return $"{segments[0]}/{segments[1]}";
    }

    private static string? DetectImageFormatLabel(string path)
    {
        var extension = Path.GetExtension(path)?.Trim().ToLowerInvariant();
        return extension switch
        {
            ".vmdk" => "VMDK",
            ".vhd" => "VHD",
            ".vhdx" => "VHDX",
            ".qcow2" => "QCOW2",
            _ => null,
        };
    }

    private static long? TryReadInt64(ManagementObject obj, string propertyName)
    {
        var raw = obj[propertyName];
        if (raw is null)
        {
            return null;
        }

        return long.TryParse(raw.ToString(), out var value) ? value : null;
    }

    private static int? TryReadInt32(ManagementObject obj, string propertyName)
    {
        var raw = obj[propertyName];
        if (raw is null)
        {
            return null;
        }

        return int.TryParse(raw.ToString(), out var value) ? value : null;
    }

    private IEnumerable<SourceCandidate> EnumeratePhysicalDisks(CancellationToken cancellationToken)
    {
        const string query = "SELECT Index, Model, Size, BytesPerSector, Partitions FROM Win32_DiskDrive";
        using var searcher = new ManagementObjectSearcher(query);
        using var disks = searcher.Get();

        foreach (ManagementObject disk in disks)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var index = TryReadInt32(disk, "Index");
            var size = TryReadInt64(disk, "Size");
            var sectorSize = TryReadInt32(disk, "BytesPerSector");
            var partitionCount = TryReadInt32(disk, "Partitions");
            var model = disk["Model"]?.ToString()?.Trim();

            if (index is null)
            {
                continue;
            }

            yield return new SourceCandidate(
                Id: $"physical-{index}",
                Kind: RecoverySourceKind.PhysicalDisk,
                DisplayName: $"Disk {index}: {model ?? "Unknown Model"} ({FormatBytes(size)})",
                DevicePath: $"\\\\.\\PhysicalDrive{index}",
                FileSystem: null,
                SizeBytes: size,
                SectorSizeBytes: sectorSize,
                DiskIndex: index,
                VolumeIdentity: null,
                SourcePath: null,
                ReadOnlyEnforced: true,
                VolumeLabel: null,
                MountedPaths: null,
                PartitionInfo: partitionCount.HasValue ? $"{partitionCount.Value} partitions" : null);
        }
    }

    private IEnumerable<SourceCandidate> EnumerateLogicalVolumes(
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, DriveSnapshot> driveSnapshots)
    {
        foreach (var snapshot in driveSnapshots.Values.OrderBy(s => s.RootPath, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var rootPath = snapshot.RootPath;
            var devicePath = $"\\\\.\\{rootPath.TrimEnd('\\')}";

            yield return new SourceCandidate(
                Id: $"volume-{rootPath.TrimEnd('\\').ToUpperInvariant()}",
                Kind: RecoverySourceKind.Volume,
                DisplayName: $"Volume {rootPath} ({snapshot.FileSystem}, {FormatBytes(snapshot.TotalSize)})",
                DevicePath: devicePath,
                FileSystem: snapshot.FileSystem,
                SizeBytes: snapshot.TotalSize,
                SectorSizeBytes: snapshot.SectorSizeBytes,
                DiskIndex: snapshot.DiskIndex,
                VolumeIdentity: snapshot.VolumeIdentity,
                SourcePath: rootPath,
                ReadOnlyEnforced: true,
                VolumeLabel: snapshot.VolumeLabel,
                MountedPaths: string.Join(";", snapshot.MountPaths),
                PartitionInfo: null);
        }
    }

    private IEnumerable<SourceCandidate> EnumeratePartitions(
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, DriveSnapshot> driveSnapshots)
    {
        const string query = "SELECT DeviceID, DiskIndex, Index, Size, Type FROM Win32_DiskPartition";
        using var searcher = new ManagementObjectSearcher(query);
        using var partitions = searcher.Get();

        foreach (ManagementObject partition in partitions)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var deviceId = partition["DeviceID"]?.ToString();
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                continue;
            }

            var diskIndex = TryReadInt32(partition, "DiskIndex");
            var partitionIndex = TryReadInt32(partition, "Index");
            var size = TryReadInt64(partition, "Size");
            var type = partition["Type"]?.ToString();
            var logicalRoots = ResolveLogicalRootsForPartition(deviceId);

            var firstSnapshot = logicalRoots
                .Select(root => root.TrimEnd('\\').ToUpperInvariant())
                .Select(key => driveSnapshots.TryGetValue(key, out var snapshot) ? snapshot : null)
                .FirstOrDefault(s => s is not null);

            var partitionNumber = ExtractPartitionNumber(deviceId) ?? partitionIndex;
            var devicePath = diskIndex.HasValue && partitionNumber.HasValue
                ? $"\\\\.\\Harddisk{diskIndex.Value}Partition{partitionNumber.Value}"
                : null;

            var mountPaths = new List<string>();
            foreach (var root in logicalRoots)
            {
                mountPaths.Add(root);
                var key = root.TrimEnd('\\').ToUpperInvariant();
                if (driveSnapshots.TryGetValue(key, out var snapshot))
                {
                    mountPaths.AddRange(snapshot.MountPaths);
                }
            }

            var uniqueMountPaths = mountPaths
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            yield return new SourceCandidate(
                Id: $"partition-{diskIndex ?? -1}-{partitionNumber ?? partitionIndex ?? -1}",
                Kind: RecoverySourceKind.Partition,
                DisplayName: $"Partition D{diskIndex?.ToString() ?? "?"}:P{partitionNumber?.ToString() ?? partitionIndex?.ToString() ?? "?"} ({FormatBytes(size)})",
                DevicePath: devicePath,
                FileSystem: firstSnapshot?.FileSystem,
                SizeBytes: size,
                SectorSizeBytes: firstSnapshot?.SectorSizeBytes,
                DiskIndex: diskIndex,
                VolumeIdentity: firstSnapshot?.VolumeIdentity,
                SourcePath: firstSnapshot?.RootPath,
                ReadOnlyEnforced: true,
                VolumeLabel: firstSnapshot?.VolumeLabel,
                MountedPaths: string.Join(";", uniqueMountPaths),
                PartitionInfo: type ?? "Partition");
        }
    }

    private IEnumerable<SourceCandidate> EnumeratePhysicalDisksFallback(CancellationToken cancellationToken)
    {
        var indexes = QueryDosDeviceNames()
            .Select(ParsePhysicalDiskIndex)
            .Where(index => index.HasValue)
            .Select(index => index!.Value)
            .Distinct()
            .OrderBy(index => index)
            .ToArray();

        foreach (var index in indexes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var devicePath = $@"\\.\PhysicalDrive{index}";
            long? sizeBytes = null;
            int? sectorSize = null;
            var partitionInfo = "Win32 fallback";

            using var handle = TryOpenMetadataHandle(devicePath, out var openErrorCode);
            if (handle is not null && TryQueryDiskGeometry(handle, out var size, out var sector))
            {
                sizeBytes = size;
                sectorSize = sector;
            }
            else if (openErrorCode == ERROR_ACCESS_DENIED)
            {
                partitionInfo = "Win32 fallback (metadata requires elevation)";
            }

            yield return new SourceCandidate(
                Id: $"physical-fallback-{index}",
                Kind: RecoverySourceKind.PhysicalDisk,
                DisplayName: $"Disk {index} ({FormatBytes(sizeBytes)})",
                DevicePath: devicePath,
                FileSystem: null,
                SizeBytes: sizeBytes,
                SectorSizeBytes: sectorSize,
                DiskIndex: index,
                VolumeIdentity: null,
                SourcePath: null,
                ReadOnlyEnforced: true,
                VolumeLabel: null,
                MountedPaths: null,
                PartitionInfo: partitionInfo);
        }
    }

    private IEnumerable<SourceCandidate> EnumeratePartitionsFromVolumesFallback(
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, DriveSnapshot> driveSnapshots)
    {
        var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var snapshot in driveSnapshots.Values.OrderBy(s => s.RootPath, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var openPath = ResolveVolumeOpenPath(snapshot);
            if (openPath is null)
            {
                continue;
            }

            using var handle = TryOpenMetadataHandle(openPath, out _);
            if (handle is null)
            {
                continue;
            }

            if (!TryQueryStorageDeviceNumber(handle, out var diskIndex, out var partitionNumber))
            {
                continue;
            }

            if (diskIndex < 0 || partitionNumber < 0)
            {
                continue;
            }

            var partitionKey = $"{diskIndex}:{partitionNumber}";
            if (!emitted.Add(partitionKey))
            {
                continue;
            }

            var partitionPath = $@"\\.\Harddisk{diskIndex}Partition{partitionNumber}";
            var mountPaths = snapshot.MountPaths
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Distinct(StringComparer.OrdinalIgnoreCase);

            yield return new SourceCandidate(
                Id: $"partition-fallback-{diskIndex}-{partitionNumber}",
                Kind: RecoverySourceKind.Partition,
                DisplayName: $"Partition D{diskIndex}:P{partitionNumber} ({FormatBytes(snapshot.TotalSize)})",
                DevicePath: partitionPath,
                FileSystem: snapshot.FileSystem,
                SizeBytes: snapshot.TotalSize,
                SectorSizeBytes: snapshot.SectorSizeBytes,
                DiskIndex: diskIndex,
                VolumeIdentity: snapshot.VolumeIdentity,
                SourcePath: snapshot.RootPath,
                ReadOnlyEnforced: true,
                VolumeLabel: snapshot.VolumeLabel,
                MountedPaths: string.Join(";", mountPaths),
                PartitionInfo: "Win32 fallback from mounted volume");
        }
    }

    private IEnumerable<SourceCandidate> EnumeratePartitionsSetupApiFallback(
        CancellationToken cancellationToken,
        IReadOnlyDictionary<string, DriveSnapshot> driveSnapshots)
    {
        var mountedPartitions = BuildMountedPartitionSnapshotMap(driveSnapshots);
        var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var diskIndex in EnumeratePresentDiskIndexesFromSetupApi(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            for (var partitionNumber = 1; partitionNumber <= 256; partitionNumber++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var partitionPath = $@"\\.\Harddisk{diskIndex}Partition{partitionNumber}";
                using var handle = TryOpenMetadataHandle(partitionPath, out var openErrorCode);
                if (handle is null)
                {
                    if (openErrorCode == ERROR_ACCESS_DENIED)
                    {
                        // Access denied likely indicates an existing but protected partition.
                        var accessDeniedKey = $"{diskIndex}:{partitionNumber}";
                        if (!emitted.Add(accessDeniedKey))
                        {
                            continue;
                        }

                        mountedPartitions.TryGetValue(accessDeniedKey, out var mountedSnapshot);
                        var mountedPathsForDenied = mountedSnapshot?.MountPaths
                            .Where(path => !string.IsNullOrWhiteSpace(path))
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .ToArray() ?? [];

                        yield return new SourceCandidate(
                            Id: $"partition-setupapi-{diskIndex}-{partitionNumber}",
                            Kind: RecoverySourceKind.Partition,
                            DisplayName: $"Partition D{diskIndex}:P{partitionNumber} (metadata requires elevation)",
                            DevicePath: partitionPath,
                            FileSystem: mountedSnapshot?.FileSystem,
                            SizeBytes: mountedSnapshot?.TotalSize,
                            SectorSizeBytes: mountedSnapshot?.SectorSizeBytes,
                            DiskIndex: diskIndex,
                            VolumeIdentity: mountedSnapshot?.VolumeIdentity,
                            SourcePath: mountedSnapshot?.RootPath,
                            ReadOnlyEnforced: true,
                            VolumeLabel: mountedSnapshot?.VolumeLabel,
                            MountedPaths: string.Join(";", mountedPathsForDenied),
                            PartitionInfo: "SetupAPI fallback (access denied)");
                    }

                    continue;
                }

                if (!TryQueryStorageDeviceNumber(handle, out var resolvedDisk, out var resolvedPartition))
                {
                    continue;
                }

                if (resolvedDisk < 0 || resolvedPartition <= 0)
                {
                    continue;
                }

                var partitionKey = $"{resolvedDisk}:{resolvedPartition}";
                if (!emitted.Add(partitionKey))
                {
                    continue;
                }

                long? sizeBytes = null;
                int? sectorSizeBytes = null;
                if (TryQueryDiskGeometry(handle, out var geometrySize, out var geometrySector))
                {
                    sizeBytes = geometrySize;
                    sectorSizeBytes = geometrySector;
                }

                mountedPartitions.TryGetValue(partitionKey, out var mountedSnapshotForPartition);
                var mountedPaths = mountedSnapshotForPartition?.MountPaths
                    .Where(path => !string.IsNullOrWhiteSpace(path))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray() ?? [];

                var displaySize = sizeBytes ?? mountedSnapshotForPartition?.TotalSize;

                yield return new SourceCandidate(
                    Id: $"partition-setupapi-{resolvedDisk}-{resolvedPartition}",
                    Kind: RecoverySourceKind.Partition,
                    DisplayName: $"Partition D{resolvedDisk}:P{resolvedPartition} ({FormatBytes(displaySize)})",
                    DevicePath: $@"\\.\Harddisk{resolvedDisk}Partition{resolvedPartition}",
                    FileSystem: mountedSnapshotForPartition?.FileSystem,
                    SizeBytes: sizeBytes ?? mountedSnapshotForPartition?.TotalSize,
                    SectorSizeBytes: sectorSizeBytes ?? mountedSnapshotForPartition?.SectorSizeBytes,
                    DiskIndex: resolvedDisk,
                    VolumeIdentity: mountedSnapshotForPartition?.VolumeIdentity,
                    SourcePath: mountedSnapshotForPartition?.RootPath,
                    ReadOnlyEnforced: true,
                    VolumeLabel: mountedSnapshotForPartition?.VolumeLabel,
                    MountedPaths: string.Join(";", mountedPaths),
                    PartitionInfo: mountedSnapshotForPartition is null
                        ? "SetupAPI fallback (unmounted/offline candidate)"
                        : "SetupAPI fallback (matched mounted volume)");
            }
        }
    }

    private IEnumerable<int> EnumeratePresentDiskIndexesFromSetupApi(CancellationToken cancellationToken)
    {
        var diskInterfaceGuid = GuidDevinterfaceDisk;
        var deviceInfoSet = SetupDiGetClassDevs(
            ref diskInterfaceGuid,
            IntPtr.Zero,
            IntPtr.Zero,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

        if (deviceInfoSet == InvalidDeviceInfoSetHandle)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetupDiGetClassDevs failed for disk interfaces.");
        }

        try
        {
            var indexes = new HashSet<int>();
            uint memberIndex = 0;
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var interfaceData = new SP_DEVICE_INTERFACE_DATA
                {
                    cbSize = Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>(),
                };

                var success = SetupDiEnumDeviceInterfaces(
                    deviceInfoSet,
                    IntPtr.Zero,
                    ref diskInterfaceGuid,
                    memberIndex,
                    ref interfaceData);

                if (!success)
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == ERROR_NO_MORE_ITEMS)
                    {
                        break;
                    }

                    throw new Win32Exception(error, "SetupDiEnumDeviceInterfaces failed.");
                }

                memberIndex++;
                var interfacePath = TryGetDeviceInterfacePath(deviceInfoSet, interfaceData);
                if (string.IsNullOrWhiteSpace(interfacePath))
                {
                    continue;
                }

                using var handle = TryOpenMetadataHandle(interfacePath, out _);
                if (handle is null)
                {
                    continue;
                }

                if (TryQueryStorageDeviceNumber(handle, out var diskIndex, out _)
                    && diskIndex >= 0)
                {
                    indexes.Add(diskIndex);
                }
            }

            return indexes.OrderBy(index => index).ToArray();
        }
        finally
        {
            _ = SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }
    }

    private static string? TryGetDeviceInterfacePath(IntPtr deviceInfoSet, SP_DEVICE_INTERFACE_DATA interfaceData)
    {
        var firstPass = SetupDiGetDeviceInterfaceDetail(
            deviceInfoSet,
            ref interfaceData,
            IntPtr.Zero,
            0,
            out var requiredSize,
            IntPtr.Zero);

        if (firstPass || requiredSize == 0)
        {
            return null;
        }

        var error = Marshal.GetLastWin32Error();
        if (error != ERROR_INSUFFICIENT_BUFFER)
        {
            return null;
        }

        var detailBuffer = Marshal.AllocHGlobal((int)requiredSize);
        try
        {
            var cbSize = IntPtr.Size == 8 ? 8 : 6;
            Marshal.WriteInt32(detailBuffer, cbSize);

            var success = SetupDiGetDeviceInterfaceDetail(
                deviceInfoSet,
                ref interfaceData,
                detailBuffer,
                requiredSize,
                out _,
                IntPtr.Zero);

            if (!success)
            {
                return null;
            }

            var candidatePath = Marshal.PtrToStringUni(IntPtr.Add(detailBuffer, 4));
            if (!string.IsNullOrWhiteSpace(candidatePath))
            {
                return candidatePath;
            }

            return Marshal.PtrToStringUni(IntPtr.Add(detailBuffer, cbSize));
        }
        finally
        {
            Marshal.FreeHGlobal(detailBuffer);
        }
    }

    private static Dictionary<string, DriveSnapshot> BuildMountedPartitionSnapshotMap(
        IReadOnlyDictionary<string, DriveSnapshot> driveSnapshots)
    {
        var map = new Dictionary<string, DriveSnapshot>(StringComparer.OrdinalIgnoreCase);

        foreach (var snapshot in driveSnapshots.Values)
        {
            var openPath = ResolveVolumeOpenPath(snapshot);
            if (openPath is null)
            {
                continue;
            }

            using var handle = TryOpenMetadataHandle(openPath, out _);
            if (handle is null)
            {
                continue;
            }

            if (!TryQueryStorageDeviceNumber(handle, out var diskIndex, out var partitionNumber))
            {
                continue;
            }

            if (diskIndex < 0 || partitionNumber < 0)
            {
                continue;
            }

            map[$"{diskIndex}:{partitionNumber}"] = snapshot;
        }

        return map;
    }

    private static int? ParsePhysicalDiskIndex(string deviceName)
    {
        if (!deviceName.StartsWith("PhysicalDrive", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var suffix = deviceName.Substring("PhysicalDrive".Length);
        return int.TryParse(suffix, out var value)
            ? value
            : null;
    }

    private static string? ResolveVolumeOpenPath(DriveSnapshot snapshot)
    {
        if (!string.IsNullOrWhiteSpace(snapshot.VolumeIdentity))
        {
            return snapshot.VolumeIdentity.TrimEnd('\\');
        }

        if (!string.IsNullOrWhiteSpace(snapshot.RootPath))
        {
            return $@"\\.\{snapshot.RootPath.TrimEnd('\\')}";
        }

        return null;
    }

    private static IReadOnlyList<string> QueryDosDeviceNames()
    {
        var bufferSize = 4096;
        while (true)
        {
            var buffer = new char[bufferSize];
            var written = QueryDosDevice(null, buffer, buffer.Length);
            if (written != 0)
            {
                return ParseMultiString(buffer);
            }

            var error = Marshal.GetLastWin32Error();
            if (error == ERROR_INSUFFICIENT_BUFFER)
            {
                bufferSize *= 2;
                continue;
            }

            throw new Win32Exception(error, "QueryDosDevice failed.");
        }
    }

    private static IReadOnlyList<string> ParseMultiString(char[] buffer)
    {
        var values = new List<string>();
        var start = 0;

        for (var i = 0; i < buffer.Length; i++)
        {
            if (buffer[i] != '\0')
            {
                continue;
            }

            if (i == start)
            {
                break;
            }

            values.Add(new string(buffer, start, i - start));
            start = i + 1;
        }

        return values;
    }

    private static SafeFileHandle? TryOpenMetadataHandle(string path, out int errorCode)
    {
        var handle = CreateFile(
            path,
            dwDesiredAccess: 0,
            dwShareMode: FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            lpSecurityAttributes: IntPtr.Zero,
            dwCreationDisposition: OPEN_EXISTING,
            dwFlagsAndAttributes: 0,
            hTemplateFile: IntPtr.Zero);

        if (!handle.IsInvalid)
        {
            errorCode = 0;
            return handle;
        }

        errorCode = Marshal.GetLastWin32Error();
        handle.Dispose();
        return null;
    }

    private static bool TryQueryDiskGeometry(SafeFileHandle handle, out long sizeBytes, out int sectorSizeBytes)
    {
        sizeBytes = 0;
        sectorSizeBytes = 0;

        var output = new byte[64];
        var success = DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            IntPtr.Zero,
            0,
            output,
            output.Length,
            out var bytesReturned,
            IntPtr.Zero);

        if (!success || bytesReturned < 32)
        {
            return false;
        }

        sectorSizeBytes = BitConverter.ToInt32(output, 20);
        sizeBytes = BitConverter.ToInt64(output, 24);
        return sectorSizeBytes > 0 && sizeBytes >= 0;
    }

    private static bool TryQueryStorageDeviceNumber(
        SafeFileHandle handle,
        out int diskNumber,
        out int partitionNumber)
    {
        diskNumber = -1;
        partitionNumber = -1;

        var output = new byte[12];
        var success = DeviceIoControl(
            handle,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            IntPtr.Zero,
            0,
            output,
            output.Length,
            out var bytesReturned,
            IntPtr.Zero);

        if (!success || bytesReturned < output.Length)
        {
            return false;
        }

        diskNumber = BitConverter.ToInt32(output, 4);
        partitionNumber = BitConverter.ToInt32(output, 8);
        return true;
    }

    private static IEnumerable<string> ResolveLogicalRootsForPartition(string partitionDeviceId)
    {
        var escaped = partitionDeviceId.Replace("\\", "\\\\").Replace("'", "\\'");
        var query =
            $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{escaped}'}} WHERE AssocClass=Win32_LogicalDiskToPartition";

        using var searcher = new ManagementObjectSearcher(query);
        using var logicalDisks = searcher.Get();

        foreach (ManagementObject logicalDisk in logicalDisks)
        {
            var deviceId = logicalDisk["DeviceID"]?.ToString();
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                continue;
            }

            yield return deviceId.EndsWith('\\') ? deviceId : deviceId + "\\";
        }
    }

    private static int? ExtractPartitionNumber(string partitionDeviceId)
    {
        var match = PartitionNumberRegex().Match(partitionDeviceId);
        if (!match.Success)
        {
            return null;
        }

        return int.TryParse(match.Groups[1].Value, out var value)
            ? value
            : null;
    }

    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_NO_MORE_ITEMS = 259;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const uint IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0;
    private const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080;
    private const uint DIGCF_PRESENT = 0x00000002;
    private const uint DIGCF_DEVICEINTERFACE = 0x00000010;
    private static readonly Guid GuidDevinterfaceDisk = new("53f56307-b6bf-11d0-94f2-00a0c91efb8b");
    private static readonly IntPtr InvalidDeviceInfoSetHandle = new(-1);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        int nInBufferSize,
        [Out] byte[] lpOutBuffer,
        int nOutBufferSize,
        out int lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(
        string? lpDeviceName,
        [Out] char[] lpTargetPath,
        int ucchMax);

    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern IntPtr SetupDiGetClassDevs(
        ref Guid classGuid,
        IntPtr enumerator,
        IntPtr hwndParent,
        uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr deviceInfoSet,
        IntPtr deviceInfoData,
        ref Guid interfaceClassGuid,
        uint memberIndex,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr deviceInfoSet,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData,
        IntPtr deviceInterfaceDetailData,
        uint deviceInterfaceDetailDataSize,
        out uint requiredSize,
        IntPtr deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [GeneratedRegex(@"Partition #(\d+)", RegexOptions.IgnoreCase)]
    private static partial Regex PartitionNumberRegex();

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA
    {
        public int cbSize;
        public Guid interfaceClassGuid;
        public int flags;
        public IntPtr reserved;
    }

    private static string FormatBytes(long? bytes)
    {
        if (bytes is null)
        {
            return "size unknown";
        }

        string[] suffixes = ["B", "KB", "MB", "GB", "TB", "PB"];
        var value = (double)bytes.Value;
        var i = 0;

        while (value >= 1024 && i < suffixes.Length - 1)
        {
            value /= 1024;
            i++;
        }

        return $"{value:0.##} {suffixes[i]}";
    }

    private sealed record DriveSnapshot(
        string RootPath,
        string FileSystem,
        string VolumeLabel,
        long TotalSize,
        int? SectorSizeBytes,
        int? DiskIndex,
        string? VolumeIdentity,
        IReadOnlyList<string> MountPaths);
}
