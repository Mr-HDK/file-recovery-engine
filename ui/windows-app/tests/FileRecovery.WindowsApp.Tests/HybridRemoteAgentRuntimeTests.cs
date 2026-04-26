using FileRecovery.WindowsApp.Core.Models;
using FileRecovery.WindowsApp.Core.Services;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace FileRecovery.WindowsApp.Tests;

public sealed class HybridRemoteAgentRuntimeTests
{
    [Fact]
    public async Task HttpRuntimeRejectsInsecureNonLoopbackHttpEndpoint()
    {
        var runtime = new HttpRemoteAgentRuntime(new HttpClient(new StubHttpMessageHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)))));

        var request = new RemoteAgentRequest(
            RequestId: Guid.NewGuid(),
            Endpoint: "http://agent.example/api/run",
            Operation: RemoteAgentOperationKind.Acquisition,
            RequestedUtc: DateTimeOffset.UtcNow,
            Integrity: new RemoteAgentIntegrityMetadata("abc", "def", null));

        var response = await runtime.ExecuteAsync(request, CancellationToken.None);
        Assert.Equal(RemoteExecutionStatus.Failed, response.Status);
        Assert.Equal(RemoteExecutionErrorCode.OperationRejected, response.ErrorCode);
    }

    [Fact]
    public async Task HttpRuntimeRetriesTransientFailureThenSucceeds()
    {
        var callCount = 0;
        var expected = new RemoteAgentResponse(
            RequestId: Guid.NewGuid(),
            Status: RemoteExecutionStatus.Succeeded,
            ErrorCode: RemoteExecutionErrorCode.None,
            Message: "ok-after-retry",
            RespondedUtc: DateTimeOffset.UtcNow,
            Integrity: new RemoteAgentIntegrityMetadata("abc", "def", null));

        var handler = new StubHttpMessageHandler(_ =>
        {
            callCount++;
            if (callCount == 1)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            }

            var json = JsonSerializer.Serialize(expected, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        var runtime = new HttpRemoteAgentRuntime(httpClient);
        var request = new RemoteAgentRequest(
            RequestId: expected.RequestId,
            Endpoint: "https://agent.example/api/run",
            Operation: RemoteAgentOperationKind.Acquisition,
            RequestedUtc: DateTimeOffset.UtcNow,
            Integrity: expected.Integrity);

        var response = await runtime.ExecuteAsync(request, CancellationToken.None);
        Assert.Equal(RemoteExecutionStatus.Succeeded, response.Status);
        Assert.Equal("ok-after-retry", response.Message);
        Assert.Equal(2, callCount);
    }

    [Fact]
    public async Task HttpRuntimeAddsSessionHeadersWhenSessionMetadataPresent()
    {
        HttpRequestMessage? captured = null;
        var expected = new RemoteAgentResponse(
            RequestId: Guid.NewGuid(),
            Status: RemoteExecutionStatus.Succeeded,
            ErrorCode: RemoteExecutionErrorCode.None,
            Message: "ok",
            RespondedUtc: DateTimeOffset.UtcNow,
            Integrity: new RemoteAgentIntegrityMetadata("abc", "def", null),
            Session: new RemoteAgentSessionMetadata(
                SessionId: "session-123",
                KeyId: "key-01",
                Nonce: "nonce-01",
                ExpiresUtc: DateTimeOffset.UtcNow.AddMinutes(5),
                RequestSignatureHex: "req-sign",
                ResponseSignatureHex: "resp-sign"));

        var handler = new StubHttpMessageHandler(request =>
        {
            captured = request;
            var json = JsonSerializer.Serialize(expected, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        var runtime = new HttpRemoteAgentRuntime(httpClient);
        var requestPayload = new RemoteAgentRequest(
            RequestId: expected.RequestId,
            Endpoint: "https://agent.example/api/run",
            Operation: RemoteAgentOperationKind.Acquisition,
            RequestedUtc: DateTimeOffset.UtcNow,
            Integrity: expected.Integrity,
            Session: expected.Session);

        var responsePayload = await runtime.ExecuteAsync(requestPayload, CancellationToken.None);
        Assert.Equal(RemoteExecutionStatus.Succeeded, responsePayload.Status);
        Assert.NotNull(captured);
        Assert.True(captured!.Headers.Contains("X-FR-Session-Id"));
        Assert.True(captured.Headers.Contains("X-FR-Session-Key"));
        Assert.True(captured.Headers.Contains("X-FR-Session-Nonce"));
        Assert.True(captured.Headers.Contains("X-FR-Session-Expires"));
        Assert.True(captured.Headers.Contains("X-FR-Session-Signature"));
    }

    [Fact]
    public async Task HybridRuntimeUsesHttpPathForHttpsEndpoint()
    {
        var expected = new RemoteAgentResponse(
            RequestId: Guid.NewGuid(),
            Status: RemoteExecutionStatus.Succeeded,
            ErrorCode: RemoteExecutionErrorCode.None,
            Message: "ok",
            RespondedUtc: DateTimeOffset.UtcNow,
            Integrity: new RemoteAgentIntegrityMetadata("abc", "def", null));

        var handler = new StubHttpMessageHandler(_ =>
        {
            var json = JsonSerializer.Serialize(expected, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        var runtime = new HybridRemoteAgentRuntime(
            httpRuntime: new HttpRemoteAgentRuntime(httpClient),
            fallbackRuntime: new LoopbackRemoteAgentRuntime());

        var request = new RemoteAgentRequest(
            RequestId: expected.RequestId,
            Endpoint: "https://agent.example/api/run",
            Operation: RemoteAgentOperationKind.Acquisition,
            RequestedUtc: DateTimeOffset.UtcNow,
            Integrity: expected.Integrity);

        var response = await runtime.ExecuteAsync(request, CancellationToken.None);
        Assert.Equal(RemoteExecutionStatus.Succeeded, response.Status);
        Assert.Equal(RemoteExecutionErrorCode.None, response.ErrorCode);
        Assert.Equal("ok", response.Message);
    }

    [Fact]
    public async Task HybridRuntimeFallsBackToLoopbackForAgentScheme()
    {
        var runtime = new HybridRemoteAgentRuntime(
            httpRuntime: new HttpRemoteAgentRuntime(new HttpClient(new StubHttpMessageHandler(_ =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError))))),
            fallbackRuntime: new LoopbackRemoteAgentRuntime());

        var request = new RemoteAgentRequest(
            RequestId: Guid.NewGuid(),
            Endpoint: "agent://nas-sidecar",
            Operation: RemoteAgentOperationKind.Acquisition,
            RequestedUtc: DateTimeOffset.UtcNow,
            Integrity: new RemoteAgentIntegrityMetadata("abc", "def", null));

        var response = await runtime.ExecuteAsync(request, CancellationToken.None);
        Assert.Equal(RemoteExecutionStatus.Succeeded, response.Status);
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _handler;

        public StubHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return _handler(request);
        }
    }
}
