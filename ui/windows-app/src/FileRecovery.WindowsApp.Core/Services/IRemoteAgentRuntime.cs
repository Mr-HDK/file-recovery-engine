using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public interface IRemoteAgentRuntime
{
    Task<RemoteAgentResponse> ExecuteAsync(RemoteAgentRequest request, CancellationToken cancellationToken);
}
