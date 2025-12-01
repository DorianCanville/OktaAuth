using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace OktaAuthWPF.Service
{
    /// <summary>
    /// Client HTTP centralisé qui gère l'ajout du token et le rafraîchissement automatique en cas de 401.
    /// </summary>
    public class ApiClientService
    {
        private readonly AuthService _authService;
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);

        public ApiClientService(AuthService authService, HttpClient? httpClient = null)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _httpClient = httpClient ?? new HttpClient();
        }

        /// <summary>
        /// Envoie une requête construite via <paramref name="requestFactory"/>.
        /// Si 401, tente un refresh (une seule fois) puis retente.
        /// </summary>
        public async Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> requestFactory, CancellationToken cancellationToken = default)
        {
            if (requestFactory == null) throw new ArgumentNullException(nameof(requestFactory));

            // Première tentative
            var request = requestFactory();
            AttachAccessToken(request);
            var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

            if (response.StatusCode != HttpStatusCode.Unauthorized)
            {
                return response;
            }

            // 401 -> tentative de refresh (synchronisée)
            response.Dispose();

            var refreshed = await TryRefreshOnceAsync(cancellationToken).ConfigureAwait(false);
            if (!refreshed)
            {
                // Retourner un 401 au caller pour qu'il gère (UI, re-login, etc.)
                return new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    RequestMessage = requestFactory()
                };
            }

            // Retenter une fois avec le nouveau token
            var retryRequest = requestFactory();
            AttachAccessToken(retryRequest);
            return await _httpClient.SendAsync(retryRequest, cancellationToken).ConfigureAwait(false);
        }

        private void AttachAccessToken(HttpRequestMessage request)
        {
            var token = _authService.GetAccessToken();
            if (!string.IsNullOrEmpty(token))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            }
        }

        private async Task<bool> TryRefreshOnceAsync(CancellationToken cancellationToken)
        {
            await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // On tente le refresh via AuthService. Il doit gérer l'absence de refresh token.
                return await _authService.TryRefreshAsync().ConfigureAwait(false);
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        /// <summary>
        /// Helper pour GET simple qui renvoie le contenu en string ou lève UnauthorizedAccessException si 401.
        /// </summary>
        public async Task<string> GetStringAsync(string url, CancellationToken cancellationToken = default)
        {
            var response = await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, url), cancellationToken).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
                throw new UnauthorizedAccessException("Token invalide / non rafraîchi.");

            response.EnsureSuccessStatusCode();
            return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}
