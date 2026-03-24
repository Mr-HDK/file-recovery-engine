using FileRecovery.WindowsApp.Core.Engine;
using FileRecovery.WindowsApp.Core.Models;
using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;

namespace FileRecovery.WindowsApp.Tests;

public sealed class HostNtfsStreamRecoveryTests
{
    private const uint RecoveryDiagCompressedAttribute = 0x0004;
    private const uint RecoveryDiagEncryptedAttribute = 0x0010;
    private const uint RecoveryDiagUnsupportedCompressed = 0x0020;
    private const uint RecoveryDiagUnsupportedEncrypted = 0x0040;

    [Fact]
    [Trait("Category", "HostIntegration")]
    public void HostIntegration_RecoversCompressedAndEncryptedDeletedStreamsWithExpectedDiagnostics()
    {
        if (!HostIntegrationEnabled())
        {
            return;
        }

        Assert.True(
            IsAdministrator(),
            "Host integration requires elevated PowerShell (Administrator).");

        if (!NativeEngineProbe.IsHealthy())
        {
            Console.WriteLine(
                "Host integration notice: skipping because file_recovery_engine.dll is unavailable in this test runtime.");
            return;
        }

        using var fixture = NtfsHostFixture.Create();
        var sourcePath = $@"\\.\{fixture.DriveLetter}:";
        var outputRoot = Path.Combine(fixture.WorkingDirectory, "recovered");
        Directory.CreateDirectory(outputRoot);

        var compressedName = $"fr-host-compressed-{Guid.NewGuid():N}.txt";
        var encryptedName = $"fr-host-encrypted-{Guid.NewGuid():N}.txt";

        fixture.CreateCompressedDeletedFile(compressedName);
        var encryptedPrepared = fixture.TryCreateEncryptedDeletedFile(encryptedName, out var encryptedSkipReason);
        if (!encryptedPrepared)
        {
            Console.WriteLine($"Host integration notice: encrypted-file validation skipped ({encryptedSkipReason}).");
        }

        var open = NativeEngineProbe.OpenSourceReadOnlySession(sourcePath, RecoverySourceKind.Volume);
        if (!open.EngineAvailable)
        {
            Console.WriteLine(
                $"Host integration notice: skipping because native engine runtime is unavailable ({open.Message}, {open.StatusCode}).");
            return;
        }
        Assert.True(open.Opened, $"Source open failed: {open.Message} ({open.StatusCode})");

        try
        {
            var quickScan = NativeEngineProbe.QuickScanNtfsFromSession(open.SessionId, maxRecords: 262_144);
            Assert.True(quickScan.Success, $"Quick scan failed: {quickScan.Message} ({quickScan.StatusCode})");

            var candidatesResult = NativeEngineProbe.GetNtfsQuickScanCandidatesFromSession(
                open.SessionId,
                maxRecords: 262_144,
                candidateCapacity: 4096);
            Assert.True(
                candidatesResult.Success,
                $"Candidate query failed: {candidatesResult.Message} ({candidatesResult.StatusCode})");

            var compressedCandidate = candidatesResult.Candidates.FirstOrDefault(candidate =>
                candidate.Deleted
                && string.Equals(candidate.Name, compressedName, StringComparison.OrdinalIgnoreCase));
            Assert.NotNull(compressedCandidate);

            var compressedOutput = Path.Combine(outputRoot, "compressed.bin");
            var compressedRecovery = NativeEngineProbe.RecoverNtfsCandidateToFile(
                open.SessionId,
                compressedCandidate!.RecordNumber,
                compressedOutput);

            Assert.True(
                compressedRecovery.Success,
                $"Compressed recovery failed: {compressedRecovery.Message} ({compressedRecovery.StatusCode})");
            Assert.False(compressedRecovery.Partial);
            Assert.True(File.Exists(compressedOutput), "Compressed output file was not created.");
            Assert.True(compressedRecovery.BytesWritten > 0);
            Assert.NotEqual(0u, compressedRecovery.DiagnosticsFlags & RecoveryDiagCompressedAttribute);
            Assert.Equal(0u, compressedRecovery.DiagnosticsFlags & RecoveryDiagUnsupportedCompressed);

            if (encryptedPrepared)
            {
                var encryptedCandidate = candidatesResult.Candidates.FirstOrDefault(candidate =>
                    candidate.Deleted
                    && string.Equals(candidate.Name, encryptedName, StringComparison.OrdinalIgnoreCase));
                Assert.NotNull(encryptedCandidate);

                var encryptedOutput = Path.Combine(outputRoot, "encrypted.bin");
                var encryptedRecovery = NativeEngineProbe.RecoverNtfsCandidateToFile(
                    open.SessionId,
                    encryptedCandidate!.RecordNumber,
                    encryptedOutput);

                Assert.True(
                    encryptedRecovery.Success,
                    $"Encrypted recovery failed: {encryptedRecovery.Message} ({encryptedRecovery.StatusCode})");
                Assert.True(encryptedRecovery.Partial);
                Assert.True(File.Exists(encryptedOutput), "Encrypted output file was not created.");
                Assert.True(encryptedRecovery.BytesWritten > 0);
                Assert.NotEqual(0u, encryptedRecovery.DiagnosticsFlags & RecoveryDiagEncryptedAttribute);
                Assert.NotEqual(0u, encryptedRecovery.DiagnosticsFlags & RecoveryDiagUnsupportedEncrypted);
            }
        }
        finally
        {
            NativeEngineProbe.CloseSourceSession(open.SessionId);
        }
    }

    private static bool HostIntegrationEnabled()
    {
        var value = Environment.GetEnvironmentVariable("FR_RUN_HOST_INTEGRATION");
        return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private sealed class NtfsHostFixture : IDisposable
    {
        private readonly string _vhdPath;
        private readonly string _workingDirectory;
        private readonly char _driveLetter;
        private bool _disposed;

        private NtfsHostFixture(string workingDirectory, string vhdPath, char driveLetter)
        {
            _workingDirectory = workingDirectory;
            _vhdPath = vhdPath;
            _driveLetter = driveLetter;
        }

        public string WorkingDirectory => _workingDirectory;
        public char DriveLetter => _driveLetter;

        public static NtfsHostFixture Create()
        {
            var root = Path.Combine(Path.GetTempPath(), "fr-host-integration", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);

            var vhdPath = Path.Combine(root, "ntfs-streams.vhd");
            var driveLetter = SelectAvailableDriveLetter();
            var script = string.Join(
                Environment.NewLine,
                $@"create vdisk file=""{vhdPath}"" maximum=256 type=expandable",
                $@"select vdisk file=""{vhdPath}""",
                "attach vdisk",
                "create partition primary",
                "format fs=ntfs quick label=FRHOST",
                $@"assign letter={driveLetter}");

            RunDiskPart(script);

            var rootPath = $@"{driveLetter}:\";
            var ready = SpinWait.SpinUntil(
                () => Directory.Exists(rootPath),
                TimeSpan.FromSeconds(20));
            if (!ready)
            {
                throw new InvalidOperationException($"Mounted drive {rootPath} was not ready in time.");
            }

            return new NtfsHostFixture(root, vhdPath, driveLetter);
        }

        public void CreateCompressedDeletedFile(string fileName)
        {
            var path = Path.Combine($@"{_driveLetter}:\", fileName);
            var payload = string.Concat(Enumerable.Repeat("COMPRESSED-DATA-", 4096));
            File.WriteAllText(path, payload);

            RunProcessOrThrow(
                "compact",
                $@"/c /i ""{path}""",
                "compact /c");

            File.Delete(path);
        }

        public bool TryCreateEncryptedDeletedFile(string fileName, out string skipReason)
        {
            var path = Path.Combine($@"{_driveLetter}:\", fileName);
            var rootPath = $@"{_driveLetter}:\";
            if (!VolumeSupportsEncryption(rootPath))
            {
                skipReason = "volume does not report EFS support";
                return false;
            }

            var payload = string.Concat(Enumerable.Repeat("ENCRYPTED-DATA-", 4096));
            File.WriteAllText(path, payload);

            var result = RunProcess(
                "cipher",
                $@"/e /a ""{path}""");
            if (result.ExitCode != 0)
            {
                skipReason = $"cipher /e unavailable (exit {result.ExitCode})";
                TryDeleteFile(path);
                return false;
            }

            var attributes = File.GetAttributes(path);
            if (!attributes.HasFlag(FileAttributes.Encrypted))
            {
                skipReason = "cipher completed but file is not marked encrypted";
                TryDeleteFile(path);
                return false;
            }

            File.Delete(path);
            skipReason = string.Empty;
            return true;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            try
            {
                if (Directory.Exists($@"{_driveLetter}:\"))
                {
                    RunDiskPart(string.Join(
                        Environment.NewLine,
                        $@"select vdisk file=""{_vhdPath}""",
                        "detach vdisk"));
                }
            }
            catch
            {
                // best-effort cleanup
            }

            try
            {
                if (File.Exists(_vhdPath))
                {
                    File.Delete(_vhdPath);
                }
            }
            catch
            {
                // best-effort cleanup
            }

            try
            {
                if (Directory.Exists(_workingDirectory))
                {
                    Directory.Delete(_workingDirectory, recursive: true);
                }
            }
            catch
            {
                // best-effort cleanup
            }
        }

        private static char SelectAvailableDriveLetter()
        {
            var used = DriveInfo.GetDrives()
                .Select(drive => char.ToUpperInvariant(drive.Name[0]))
                .ToHashSet();

            for (var letter = 'R'; letter <= 'Z'; letter++)
            {
                if (!used.Contains(letter))
                {
                    return letter;
                }
            }

            throw new InvalidOperationException("No available drive letter in the R:..Z: range.");
        }

        private static void RunDiskPart(string scriptContent)
        {
            var scriptPath = Path.Combine(Path.GetTempPath(), $"fr-diskpart-{Guid.NewGuid():N}.txt");
            File.WriteAllText(scriptPath, scriptContent);

            try
            {
                var result = RunProcess("diskpart", $@"/s ""{scriptPath}""");
                var output = $"{result.StdOut}{Environment.NewLine}{result.StdErr}";
                if (result.ExitCode != 0
                    || output.Contains("DiskPart has encountered an error", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"diskpart failed with exit code {result.ExitCode}.{Environment.NewLine}{output}");
                }
            }
            finally
            {
                try
                {
                    if (File.Exists(scriptPath))
                    {
                        File.Delete(scriptPath);
                    }
                }
                catch
                {
                    // best-effort cleanup
                }
            }
        }

        private static void RunProcessOrThrow(string fileName, string arguments, string description)
        {
            var result = RunProcess(fileName, arguments);
            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"{description} failed with exit code {result.ExitCode}.{Environment.NewLine}{result.StdOut}{Environment.NewLine}{result.StdErr}");
            }
        }

        private static ProcessResult RunProcess(string fileName, string arguments)
        {
            var startInfo = new ProcessStartInfo(fileName, arguments)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException($"Failed to start process: {fileName}");
            var stdOut = process.StandardOutput.ReadToEnd();
            var stdErr = process.StandardError.ReadToEnd();
            process.WaitForExit();

            return new ProcessResult(process.ExitCode, stdOut, stdErr);
        }

        private static bool VolumeSupportsEncryption(string rootPath)
        {
            var volumeName = new StringBuilder(261);
            var fileSystemName = new StringBuilder(261);
            var success = GetVolumeInformation(
                rootPath,
                volumeName,
                volumeName.Capacity,
                out _,
                out _,
                out var fileSystemFlags,
                fileSystemName,
                fileSystemName.Capacity);

            if (!success)
            {
                return false;
            }

            return (fileSystemFlags & FileSupportsEncryption) != 0;
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // best-effort cleanup
            }
        }

        private const uint FileSupportsEncryption = 0x00020000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformation(
            string rootPathName,
            StringBuilder volumeNameBuffer,
            int volumeNameSize,
            out uint volumeSerialNumber,
            out uint maximumComponentLength,
            out uint fileSystemFlags,
            StringBuilder fileSystemNameBuffer,
            int nFileSystemNameSize);

        private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
    }
}
