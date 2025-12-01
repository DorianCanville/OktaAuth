
using Duende.IdentityModel.OidcClient.Browser;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace OktaAuthWPF.Service.Browser
{
    public class SystemBrowser : IBrowser
    {
        private readonly int _port;

        public SystemBrowser(int port = 7890)
        {
            _port = port;
        }

        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken cancellationToken = default)
        {
            using (var listener = new HttpListener())
            {
                // On écoute sur le port défini dans Okta
                listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
                listener.Start();

                // On ouvre le navigateur système avec l'URL de login Okta
                OpenBrowser(options.StartUrl);

                // On attend le retour (le redirect)
                var context = await listener.GetContextAsync();
                var response = context.Response;

                // On renvoie une petite page HTML pour dire à l'user de fermer l'onglet
                string responseString = "<html><body><h1>Authentification reussie !</h1><p>Vous pouvez retourner sur l'application.</p></body></html>";
                var buffer = Encoding.UTF8.GetBytes(responseString);
                response.ContentLength64 = buffer.Length;
                var responseOutput = response.OutputStream;
                await responseOutput.WriteAsync(buffer, 0, buffer.Length);
                responseOutput.Close();

                // On renvoie l'URL complète (avec le code) à OidcClient
                return new BrowserResult
                {
                    Response = context.Request.Url.ToString(),
                    ResultType = BrowserResultType.Success
                };
            }
        }

        private void OpenBrowser(string url)
        {
            try
            {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
            catch
            {
                // Hack pour Linux/Mac si jamais, mais sur Windows le dessus suffit
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    url = url.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
            }
        }
    }
}
