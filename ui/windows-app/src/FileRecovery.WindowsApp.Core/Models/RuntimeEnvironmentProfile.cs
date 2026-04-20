namespace FileRecovery.WindowsApp.Core.Models;

public sealed record RuntimeEnvironmentProfile(
    RuntimeEnvironmentMode Mode,
    string BootDrive,
    bool MiniNtRegistryDetected,
    bool WinPeOverrideDetected,
    bool BootDriveLooksLikeWinPe
)
{
    public bool IsWinPe => Mode == RuntimeEnvironmentMode.WinPe;
}
