using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class HybridRemoteAgentRuntime : IRemoteAgentRuntime
{
    private readonly IRemoteAgentRuntime _httpRuntime;
    private readonly IRemoteAgentRuntime _fallbackRuntime;

    public HybridRemoteAgentRuntime(
        IRemoteAgentRuntime? httpRuntime = null,
        IRemoteAgentRuntime? fallbackRuntime = null)
    {
        _httpRuntime = httpRuntime ?? new HttpRemoteAgentRuntime();
        _fallbackRuntime = fallbackRuntime ?? new LoopbackRemoteAgentRuntime();
    }

    public Task<RemoteAgentResponse> ExecuteAsync(RemoteAgentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Uri.TryCreate(request.Endpoint, UriKind.Absolute, out var endpoint)
            && (string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            return _httpRuntime.ExecuteAsync(request, cancellationToken);
        }

        return _fallbackRuntime.ExecuteAsync(request, cancellationToken);
    }
}

