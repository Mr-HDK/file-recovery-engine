namespace FileRecovery.WindowsApp.Core.Models;

public enum RecoverySourceKind
{
    PhysicalDisk = 0,
    Volume = 1,
    ImageFile = 2,
    Partition = 3,
}
