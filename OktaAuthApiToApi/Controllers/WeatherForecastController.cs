using Microsoft.AspNetCore.Mvc;
using OktaAuthApiToApi.Services;

namespace OktaAuthApiToApi.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private readonly ApiClientService _apiClient;

    public WeatherForecastController(ApiClientService apiClient)
    {
        _apiClient = apiClient;
    }

    /// <summary>
    /// Proxifie l'appel vers OktaAuthApi en s'authentifiant via Okta (Client Credentials Flow).
    /// </summary>
    [HttpGet(Name = "GetWeatherForecast")]
    public async Task<ContentResult> Get(CancellationToken cancellationToken)
    {
        // Récupère automatiquement un token Okta (mis en cache) et appelle OktaAuthApi
        string json = await _apiClient.GetStringAsync("/WeatherForecast", cancellationToken);
        return Content(json, "application/json");
    }
}
