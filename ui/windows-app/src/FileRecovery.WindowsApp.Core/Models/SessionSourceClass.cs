namespace FileRecovery.WindowsApp.Core.Models;

public static class SessionSourceClass
{
    public const string Local = "local";
    public const string AssembledRaid = "assembled_raid";
    public const string RemoteAgent = "remote_agent";
    public const string EncryptedUnlocked = "encrypted_unlocked";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Local;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            Local => Local,
            AssembledRaid => AssembledRaid,
            RemoteAgent => RemoteAgent,
            EncryptedUnlocked => EncryptedUnlocked,
            _ => Local,
        };
    }
}
