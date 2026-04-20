using System.IO;

namespace FileRecovery.WindowsApp.Core.Models;

public sealed record VisibleVolume(
    string RootPath,
    bool IsReady,
    DriveType DriveType
);
