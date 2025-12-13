using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace OktaAuthApiToApi.Services;

public class ClientCredentialsTokenService
{
    private readonly HttpClient _http;
    private readonly string _tokenEndpoint;
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly string _scope;
    private readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);

    private string? _accessToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    public ClientCredentialsTokenService(HttpClient http, string tokenEndpoint, string clientId, string clientSecret, string scope)
    {
        _http = http;
        _tokenEndpoint = tokenEndpoint;
        _clientId = clientId;
        _clientSecret = clientSecret;
        _scope = scope;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrEmpty(_accessToken) && DateTimeOffset.UtcNow < _expiresAt)
            return _accessToken;

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!string.IsNullOrEmpty(_accessToken) && DateTimeOffset.UtcNow < _expiresAt)
                return _accessToken;

            var req = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint);
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["scope"] = _scope
            };
            req.Content = new FormUrlEncodedContent(form);

            // Basic auth (client_secret_basic)
            var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_clientId}:{_clientSecret}"));
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);

            var res = await _http.SendAsync(req, cancellationToken).ConfigureAwait(false);
            res.EnsureSuccessStatusCode();

            var json = await res.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var accessToken = root.GetProperty("access_token").GetString() ?? throw new InvalidOperationException("No access_token");
            var expiresIn = root.GetProperty("expires_in").GetInt32();

            _accessToken = accessToken;
            // sous-estimer la durée pour sécurité (slack 60s)
            _expiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn - 60);

            return _accessToken;
        }
        finally
        {
            _lock.Release();
        }
    }
}