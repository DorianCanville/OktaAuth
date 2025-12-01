using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using OktaAuthWPF.Service;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

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

        public MainViewModel()
        {
            _authService = new AuthService();
            // Réutilise le même HttpClient interne du service si besoin, sinon laisser par défaut
            _apiClient = new ApiClientService(_authService);
        }

        [RelayCommand]
        private async Task Login()
        {
            StatusMessage = "Connexion en cours...";
            var result = await _authService.Login();

            if (result.IsError)
            {
                StatusMessage = $"Erreur : {result.Error}";
                return;
            }

            StatusMessage = $"Connecté ! Bonjour {result.User.Identity.Name}";
        }

        [RelayCommand]
        private async Task CallApi()
        {
            var apiUrl = "http://localhost:5000/WeatherForecast";

            try
            {
                var json = await _apiClient.GetStringAsync(apiUrl);
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
