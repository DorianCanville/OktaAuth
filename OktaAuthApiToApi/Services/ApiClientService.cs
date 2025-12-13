using System.Net.Http.Headers;

namespace OktaAuthApiToApi.Services;

public class ApiClientService
{
    private readonly HttpClient _http;
    private readonly ClientCredentialsTokenService _tokenService;

    public ApiClientService(HttpClient http, ClientCredentialsTokenService tokenService)
    {
        _http = http;
        _tokenService = tokenService;
    }

    public async Task<string> GetStringAsync(string url, CancellationToken cancellationToken = default)
    {
        var token = await _tokenService.GetTokenAsync(cancellationToken).ConfigureAwait(false);

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var res = await _http.SendAsync(req, cancellationToken).ConfigureAwait(false);
        res.EnsureSuccessStatusCode();
        return await res.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }
}