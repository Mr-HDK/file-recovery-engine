using FileRecovery.WindowsApp.Core.Models;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class HttpRemoteAgentRuntime : IRemoteAgentRuntime
{
    private readonly HttpClient _httpClient;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public HttpRemoteAgentRuntime(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient();
    }

    public async Task<RemoteAgentResponse> ExecuteAsync(RemoteAgentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!Uri.TryCreate(request.Endpoint, UriKind.Absolute, out var endpoint))
        {
            return new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.InvalidRequest,
                ErrorCode: RemoteExecutionErrorCode.EndpointRequired,
                Message: "Remote agent endpoint is invalid.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity);
        }

        if (!string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.Unavailable,
                ErrorCode: RemoteExecutionErrorCode.EndpointUnreachable,
                Message: "HTTP remote runtime only supports http/https endpoints.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity);
        }

        try
        {
            var payload = JsonSerializer.Serialize(request, JsonOptions);
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");
            using var response = await _httpClient.PostAsync(endpoint, content, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new RemoteAgentResponse(
                    RequestId: request.RequestId,
                    Status: RemoteExecutionStatus.Failed,
                    ErrorCode: RemoteExecutionErrorCode.OperationRejected,
                    Message: $"Remote agent HTTP error {(int)response.StatusCode}.",
                    RespondedUtc: DateTimeOffset.UtcNow,
                    Integrity: request.Integrity);
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(json))
            {
                return new RemoteAgentResponse(
                    RequestId: request.RequestId,
                    Status: RemoteExecutionStatus.Failed,
                    ErrorCode: RemoteExecutionErrorCode.InvalidResponse,
                    Message: "Remote agent returned empty response payload.",
                    RespondedUtc: DateTimeOffset.UtcNow,
                    Integrity: request.Integrity);
            }

            var parsed = JsonSerializer.Deserialize<RemoteAgentResponse>(json, JsonOptions);
            if (parsed is null)
            {
                return new RemoteAgentResponse(
                    RequestId: request.RequestId,
                    Status: RemoteExecutionStatus.Failed,
                    ErrorCode: RemoteExecutionErrorCode.InvalidResponse,
                    Message: "Remote agent response could not be parsed.",
                    RespondedUtc: DateTimeOffset.UtcNow,
                    Integrity: request.Integrity);
            }

            return parsed with
            {
                RequestId = parsed.RequestId == Guid.Empty ? request.RequestId : parsed.RequestId,
                Integrity = parsed.Integrity ?? request.Integrity,
            };
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.Unavailable,
                ErrorCode: RemoteExecutionErrorCode.EndpointUnreachable,
                Message: "Remote agent request timed out.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity);
        }
        catch (HttpRequestException ex)
        {
            return new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.Unavailable,
                ErrorCode: RemoteExecutionErrorCode.EndpointUnreachable,
                Message: $"Remote agent endpoint unreachable: {ex.Message}",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity);
        }
    }
}
