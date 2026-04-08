namespace FileRecovery.WindowsApp.Core.Models;

public enum ImageReadErrorPolicy
{
    FailFast = 0,
    ContinueWithZeroFill = 1,
}
