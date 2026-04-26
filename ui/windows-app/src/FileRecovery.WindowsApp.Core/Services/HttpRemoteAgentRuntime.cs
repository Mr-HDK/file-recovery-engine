using FileRecovery.WindowsApp.Core.Models;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace FileRecovery.WindowsApp.Core.Services;

public sealed class HttpRemoteAgentRuntime : IRemoteAgentRuntime
{
    private readonly HttpClient _httpClient;
    private const int MaxAttempts = 3;
    private const int InitialBackoffMs = 250;
    private const int MaxResponseBytes = 1024 * 1024;

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

        if (!IsAllowedTransport(endpoint))
        {
            return new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.Failed,
                ErrorCode: RemoteExecutionErrorCode.OperationRejected,
                Message: "Remote agent endpoint must use HTTPS unless host is loopback.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity);
        }

        try
        {
            var payload = JsonSerializer.Serialize(request, JsonOptions);
            for (var attempt = 1; attempt <= MaxAttempts; attempt++)
            {
                using var requestMessage = new HttpRequestMessage(HttpMethod.Post, endpoint);
                requestMessage.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                requestMessage.Headers.TryAddWithoutValidation("X-FR-Request-Id", request.RequestId.ToString("D"));
                requestMessage.Headers.TryAddWithoutValidation("X-FR-Request-Hash", request.Integrity.RequestHashHex);
                if (!string.IsNullOrWhiteSpace(request.Integrity.PayloadHashHex))
                {
                    requestMessage.Headers.TryAddWithoutValidation("X-FR-Payload-Hash", request.Integrity.PayloadHashHex);
                }
                if (request.Session is not null)
                {
                    requestMessage.Headers.TryAddWithoutValidation("X-FR-Session-Id", request.Session.SessionId);
                    requestMessage.Headers.TryAddWithoutValidation("X-FR-Session-Key", request.Session.KeyId);
                    requestMessage.Headers.TryAddWithoutValidation("X-FR-Session-Nonce", request.Session.Nonce);
                    requestMessage.Headers.TryAddWithoutValidation("X-FR-Session-Expires", request.Session.ExpiresUtc.ToString("O"));
                    if (!string.IsNullOrWhiteSpace(request.Session.RequestSignatureHex))
                    {
                        requestMessage.Headers.TryAddWithoutValidation("X-FR-Session-Signature", request.Session.RequestSignatureHex);
                    }
                }

                try
                {
                    using var response = await _httpClient.SendAsync(requestMessage, cancellationToken);
                    if (!response.IsSuccessStatusCode)
                    {
                        if (attempt < MaxAttempts && IsTransientStatusCode(response.StatusCode))
                        {
                            await DelayBeforeRetryAsync(attempt, cancellationToken);
                            continue;
                        }

                        return new RemoteAgentResponse(
                            RequestId: request.RequestId,
                            Status: RemoteExecutionStatus.Failed,
                            ErrorCode: RemoteExecutionErrorCode.OperationRejected,
                            Message: $"Remote agent HTTP error {(int)response.StatusCode}.",
                            RespondedUtc: DateTimeOffset.UtcNow,
                            Integrity: request.Integrity);
                    }

                    var responseBytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                    if (responseBytes.Length == 0)
                    {
                        return new RemoteAgentResponse(
                            RequestId: request.RequestId,
                            Status: RemoteExecutionStatus.Failed,
                            ErrorCode: RemoteExecutionErrorCode.InvalidResponse,
                            Message: "Remote agent returned empty response payload.",
                            RespondedUtc: DateTimeOffset.UtcNow,
                            Integrity: request.Integrity);
                    }

                    if (responseBytes.Length > MaxResponseBytes)
                    {
                        return new RemoteAgentResponse(
                            RequestId: request.RequestId,
                            Status: RemoteExecutionStatus.Failed,
                            ErrorCode: RemoteExecutionErrorCode.InvalidResponse,
                            Message: $"Remote agent response exceeded {MaxResponseBytes} bytes.",
                            RespondedUtc: DateTimeOffset.UtcNow,
                            Integrity: request.Integrity);
                    }

                    var json = Encoding.UTF8.GetString(responseBytes);
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
                        Session = parsed.Session ?? request.Session,
                    };
                }
                catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    if (attempt < MaxAttempts)
                    {
                        await DelayBeforeRetryAsync(attempt, cancellationToken);
                        continue;
                    }

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
                    if (attempt < MaxAttempts)
                    {
                        await DelayBeforeRetryAsync(attempt, cancellationToken);
                        continue;
                    }

                    return new RemoteAgentResponse(
                        RequestId: request.RequestId,
                        Status: RemoteExecutionStatus.Unavailable,
                        ErrorCode: RemoteExecutionErrorCode.EndpointUnreachable,
                        Message: $"Remote agent endpoint unreachable: {ex.Message}",
                        RespondedUtc: DateTimeOffset.UtcNow,
                        Integrity: request.Integrity);
                }
            }

            return new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.Unavailable,
                ErrorCode: RemoteExecutionErrorCode.EndpointUnreachable,
                Message: "Remote agent endpoint unreachable after retries.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new RemoteAgentResponse(
                RequestId: request.RequestId,
                Status: RemoteExecutionStatus.Unavailable,
                ErrorCode: RemoteExecutionErrorCode.EndpointUnreachable,
                Message: "Remote agent request timed out.",
                RespondedUtc: DateTimeOffset.UtcNow,
                Integrity: request.Integrity);
        }
    }

    private static bool IsAllowedTransport(Uri endpoint)
    {
        if (string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.Equals(endpoint.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return endpoint.IsLoopback
            || string.Equals(endpoint.Host, "localhost", StringComparison.OrdinalIgnoreCase)
            || string.Equals(endpoint.Host, "::1", StringComparison.OrdinalIgnoreCase)
            || endpoint.Host.StartsWith("127.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsTransientStatusCode(System.Net.HttpStatusCode statusCode)
    {
        return statusCode == System.Net.HttpStatusCode.RequestTimeout
            || (int)statusCode == 429
            || statusCode == System.Net.HttpStatusCode.InternalServerError
            || statusCode == System.Net.HttpStatusCode.BadGateway
            || statusCode == System.Net.HttpStatusCode.ServiceUnavailable
            || statusCode == System.Net.HttpStatusCode.GatewayTimeout;
    }

    private static Task DelayBeforeRetryAsync(int attempt, CancellationToken cancellationToken)
    {
        var delay = TimeSpan.FromMilliseconds(InitialBackoffMs * Math.Max(1, attempt));
        return Task.Delay(delay, cancellationToken);
    }
}
