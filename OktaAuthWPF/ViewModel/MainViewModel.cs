using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OktaAuthWPF.Service;
using System.Net.Http;

namespace OktaAuthWPF.ViewModel
{
    public partial class MainViewModel : ObservableObject
    {
        private readonly AuthService _authService;
        private readonly ApiClientService _apiClient;

        [ObservableProperty]
        private string _statusMessage = "Non connecté";

        [ObservableProperty]
        private string _apiResponse = "";

        public MainViewModel(AuthService AuthService)
        {
            _authService = AuthService;
            // Réutilise le même HttpClient interne du service si besoin, sinon laisser par défaut
            _apiClient = new ApiClientService(_authService);
        }

        [RelayCommand]
        private async Task Login()
        {
            StatusMessage = "Connexion en cours...";
            bool result = await _authService.EnsureAuthenticatedAsync();

            if (result)
            {
            }

            //if (result.IsError)
            //{
            //    StatusMessage = $"Erreur : {result.Error}";
            //    return;
            //}

            //StatusMessage = $"Connecté ! Bonjour {result.User.Identity.Name}";
        }

        [RelayCommand]
        private async Task CallApi()
        {
            string apiUrl = "http://localhost:5000/WeatherForecast";

            try
            {
                string json = await _apiClient.GetStringAsync(apiUrl);
                ApiResponse = "Succès API : \n" + json;
            }
            catch (UnauthorizedAccessException)
            {
                ApiResponse = "Token invalide ou non rafraîchi — veuillez vous reconnecter.";
                StatusMessage = "Non connecté";
            }
            catch (HttpRequestException ex)
            {
                ApiResponse = "Erreur réseau/API : " + ex.Message;
            }
            catch (Exception ex)
            {
                ApiResponse = "Exception : " + ex.Message;
            }
        }
    }
}
