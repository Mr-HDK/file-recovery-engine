namespace FileRecovery.WindowsApp.Core.Services;

public interface IPrivilegeService
{
    bool IsElevated();
}
