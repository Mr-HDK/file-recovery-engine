namespace FileRecovery.WindowsApp.Core.Persistence;

public static class FileRecoveryPaths
{
    public static string BaseDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FileRecovery");

    public static string LogDirectory => Path.Combine(BaseDirectory, "logs");
}
