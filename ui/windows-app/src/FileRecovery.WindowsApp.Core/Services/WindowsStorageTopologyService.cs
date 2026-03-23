using Microsoft.Win32.SafeHandles;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class WindowsStorageTopologyService : IStorageTopologyService
{
    private readonly ConcurrentDictionary<string, int?> _diskIndexCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int?> _sectorSizeCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, IReadOnlyList<string>> _mountPathCache = new(StringComparer.OrdinalIgnoreCase);

    public string? TryGetVolumeIdFromPath(string path)
    {
        return TryResolveVolumeContext(path)?.VolumeId;
    }

    public int? TryGetDiskIndexFromPath(string path)
    {
        var context = TryResolveVolumeContext(path);
        if (context is null)
        {
            return null;
        }

        return _diskIndexCache.GetOrAdd(context.VolumeId, ResolveDiskIndexForVolumeId);
    }

    public int? TryGetSectorSizeFromPath(string path)
    {
        var context = TryResolveVolumeContext(path);
        if (context is null)
        {
            return null;
        }

        return _sectorSizeCache.GetOrAdd(context.VolumeId, _ => ResolveSectorSizeForMountPoint(context.MountPoint));
    }

    public IReadOnlyList<string> GetMountPathsForVolumeId(string volumeId)
    {
        if (string.IsNullOrWhiteSpace(volumeId))
        {
            return [];
        }

        var normalized = NormalizeVolumeName(volumeId);
        return _mountPathCache.GetOrAdd(normalized, ResolveMountPaths);
    }

    private static VolumeContext? TryResolveVolumeContext(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var fullPath = Path.GetFullPath(path);
        var mountPoint = TryGetVolumePathName(fullPath);
        if (mountPoint is null)
        {
            return null;
        }

        var volumeId = TryGetVolumeNameFromMountPoint(mountPoint);
        if (volumeId is null)
        {
            return null;
        }

        return new VolumeContext(volumeId, mountPoint);
    }

    private static string? TryGetVolumePathName(string fullPath)
    {
        var volumePathBuilder = new StringBuilder(512);
        if (!GetVolumePathName(fullPath, volumePathBuilder, volumePathBuilder.Capacity))
        {
            return null;
        }

        return EnsureTrailingDirectorySeparator(volumePathBuilder.ToString());
    }

    private static string? TryGetVolumeNameFromMountPoint(string mountPoint)
    {
        var volumeNameBuilder = new StringBuilder(512);
        if (!GetVolumeNameForVolumeMountPoint(mountPoint, volumeNameBuilder, volumeNameBuilder.Capacity))
        {
            return null;
        }

        var volumeName = volumeNameBuilder.ToString();
        if (string.IsNullOrWhiteSpace(volumeName))
        {
            return null;
        }

        return volumeName.TrimEnd('\\');
    }

    private static string EnsureTrailingDirectorySeparator(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return path;
        }

        return path.EndsWith(Path.DirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;
    }

    private static string NormalizeVolumeName(string volumeId)
    {
        var trimmed = volumeId.Trim();
        if (!trimmed.StartsWith(@"\\?\Volume", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed;
        }

        if (!trimmed.EndsWith("\\", StringComparison.Ordinal))
        {
            return trimmed + "\\";
        }

        return trimmed;
    }

    private static string NormalizeVolumeOpenPath(string volumeId)
    {
        return NormalizeVolumeName(volumeId).TrimEnd('\\');
    }

    private static IReadOnlyList<string> ResolveMountPaths(string volumeName)
    {
        const int initialChars = 1024;
        var buffer = new char[initialChars];
        var success = GetVolumePathNamesForVolumeName(
            volumeName,
            buffer,
            (uint)buffer.Length,
            out var requiredLength);

        if (!success)
        {
            if (requiredLength <= buffer.Length || requiredLength == 0)
            {
                return [];
            }

            buffer = new char[requiredLength + 1];
            success = GetVolumePathNamesForVolumeName(
                volumeName,
                buffer,
                (uint)buffer.Length,
                out _);
            if (!success)
            {
                return [];
            }
        }

        return ParseMultiString(buffer);
    }

    private static IReadOnlyList<string> ParseMultiString(char[] buffer)
    {
        var result = new List<string>();
        var current = new StringBuilder();

        foreach (var ch in buffer)
        {
            if (ch == '\0')
            {
                if (current.Length == 0)
                {
                    break;
                }

                result.Add(current.ToString());
                current.Clear();
                continue;
            }

            current.Append(ch);
        }

        return result;
    }

    private static int? ResolveDiskIndexForVolumeId(string volumeId)
    {
        var openPath = NormalizeVolumeOpenPath(volumeId);
        using var handle = TryOpenMetadataHandle(openPath);
        if (handle is null)
        {
            return null;
        }

        return TryQueryStorageDeviceNumber(handle, out var diskNumber)
            ? diskNumber
            : null;
    }

    private static int? ResolveSectorSizeForMountPoint(string mountPoint)
    {
        var success = GetDiskFreeSpace(
            mountPoint,
            out _,
            out var bytesPerSector,
            out _,
            out _);

        return success && bytesPerSector > 0
            ? (int?)bytesPerSector
            : null;
    }

    private static SafeFileHandle? TryOpenMetadataHandle(string path)
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
            return handle;
        }

        handle.Dispose();
        return null;
    }

    private static bool TryQueryStorageDeviceNumber(SafeFileHandle handle, out int diskNumber)
    {
        diskNumber = -1;

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
        return diskNumber >= 0;
    }

    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathName(
        string lpszFileName,
        StringBuilder lpszVolumePathName,
        int cchBufferLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPoint(
        string lpszVolumeMountPoint,
        StringBuilder lpszVolumeName,
        int cchBufferLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumePathNamesForVolumeName(
        string lpszVolumeName,
        [Out] char[] lpszVolumePathNames,
        uint cchBufferLength,
        out uint lpcchReturnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetDiskFreeSpace(
        string lpRootPathName,
        out uint lpSectorsPerCluster,
        out uint lpBytesPerSector,
        out uint lpNumberOfFreeClusters,
        out uint lpTotalNumberOfClusters);

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

    private sealed record VolumeContext(
        string VolumeId,
        string MountPoint);
}
