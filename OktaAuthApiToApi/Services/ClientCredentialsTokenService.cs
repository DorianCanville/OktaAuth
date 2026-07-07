using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace OktaAuthApiToApi.Services;

public class ClientCredentialsTokenService
{
    private readonly HttpClient _http;
    private readonly string _tokenEndpoint;
    private readonly string _clientId;
    private readonly RsaSecurityKey _privateKey;
    private readonly string _scope;
    private readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);

    private string? _accessToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    public ClientCredentialsTokenService(HttpClient http, string tokenEndpoint, string clientId, string privateKeyPem, string scope)
    {
        _http = http;
        _tokenEndpoint = tokenEndpoint;
        _clientId = clientId;
        _scope = scope;

        RSA rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        _privateKey = new RsaSecurityKey(rsa);
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

            string clientAssertion = BuildClientAssertion();

            HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint);
            Dictionary<string, string> form = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["scope"] = _scope,
                ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ["client_assertion"] = clientAssertion
            };
            req.Content = new FormUrlEncodedContent(form);

            HttpResponseMessage res = await _http.SendAsync(req, cancellationToken).ConfigureAwait(false);
            res.EnsureSuccessStatusCode();

            string json = await res.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;

            string accessToken = root.GetProperty("access_token").GetString() ?? throw new InvalidOperationException("No access_token");
            int expiresIn = root.GetProperty("expires_in").GetInt32();

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

    private string BuildClientAssertion()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;

        SigningCredentials signingCredentials = new SigningCredentials(_privateKey, SecurityAlgorithms.RsaSha256);

        JwtSecurityToken jwt = new JwtSecurityToken(
            issuer: _clientId,
            audience: _tokenEndpoint,
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, _clientId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            },
            notBefore: now.UtcDateTime,
            expires: now.AddMinutes(5).UtcDateTime,
            signingCredentials: signingCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}