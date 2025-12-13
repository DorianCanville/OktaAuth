using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OktaAuthWPF.Service;
using OktaAuthWPF.ViewModel;
using System.Windows;

namespace OktaAuthWPF
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        public static IHost AppHost { get; private set; } = null!;

        public App()
        {
            AppHost = Host.CreateDefaultBuilder()
                .ConfigureServices((context, services) =>
                {
                    // Services
                    services.AddSingleton<AuthService>();
                    services.AddSingleton<UserContext>();

                    // ViewModels
                    services.AddSingleton<MainViewModel>();

                    // Views
                    services.AddSingleton<MainWindow>();
                })
                .Build();
        }

        protected override async void OnStartup(StartupEventArgs e)
        {
            await AppHost.StartAsync();

            MainWindow mainWindow = AppHost.Services.GetRequiredService<MainWindow>();
            mainWindow.Show();
        }
    }
}