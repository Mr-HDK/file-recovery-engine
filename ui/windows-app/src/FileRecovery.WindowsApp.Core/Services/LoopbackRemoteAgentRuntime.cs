using FileRecovery.WindowsApp.Core.Models;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class LoopbackRemoteAgentRuntime : IRemoteAgentRuntime
{
    public Task<RemoteAgentResponse> ExecuteAsync(RemoteAgentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(request.Endpoint))
        {
            return Task.FromResult(
                new RemoteAgentResponse(
                    RequestId: request.RequestId,
                    Status: RemoteExecutionStatus.InvalidRequest,
                    ErrorCode: RemoteExecutionErrorCode.EndpointRequired,
                    Message: "Remote agent endpoint is required.",
                    RespondedUtc: DateTimeOffset.UtcNow,
                    Integrity: request.Integrity));
        }

        var endpoint = request.Endpoint.Trim();
        if (!endpoint.Contains("://", StringComparison.Ordinal))
        {
            return Task.FromResult(
                new RemoteAgentResponse(
                    RequestId: request.RequestId,
                    Status: RemoteExecutionStatus.Unavailable,
                    ErrorCode: RemoteExecutionErrorCode.EndpointUnreachable,
                    Message: "Remote agent endpoint is unreachable.",
                    RespondedUtc: DateTimeOffset.UtcNow,
                    Integrity: request.Integrity));
        }

        return Task.FromResult(
            new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.Succeeded,
                ErrorCode: RemoteExecutionErrorCode.None,
                Message: "Remote agent operation accepted.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity));
    }
}
