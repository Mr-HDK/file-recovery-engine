using System.Security.Principal;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class WindowsPrivilegeService : IPrivilegeService
{
    public bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
