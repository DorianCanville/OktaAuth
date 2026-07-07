using OktaAuthApiToApi.Services;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();

// Lecture de la config Okta
string tokenEndpoint = builder.Configuration["Okta:TokenEndpoint"]
    ?? throw new InvalidOperationException("Okta:TokenEndpoint is missing from configuration.");
string clientId = builder.Configuration["Okta:ClientId"]
    ?? throw new InvalidOperationException("Okta:ClientId is missing from configuration.");
string privateKeyPem = builder.Configuration["Okta:PrivateKeyPem"]
    ?? throw new InvalidOperationException("Okta:PrivateKeyPem is missing from configuration.");
string scope = builder.Configuration["Okta:Scope"]
    ?? throw new InvalidOperationException("Okta:Scope is missing from configuration.");
string apiBaseUrl = builder.Configuration["Okta:ApiBaseUrl"]
    ?? throw new InvalidOperationException("Okta:ApiBaseUrl is missing from configuration.");

// HttpClient dédié aux appels vers le token endpoint Okta
builder.Services.AddHttpClient<ClientCredentialsTokenService>()
    .ConfigureHttpClient(c => c.BaseAddress = new Uri(tokenEndpoint));

// Singleton : cache du token en mémoire (évite de redemander un token à chaque requête)
builder.Services.AddSingleton(sp =>
{
    var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(ClientCredentialsTokenService));
    return new ClientCredentialsTokenService(http, tokenEndpoint, clientId, privateKeyPem, scope);
});

// HttpClient dédié aux appels vers OktaAuthApi
builder.Services.AddHttpClient<ApiClientService>()
    .ConfigureHttpClient(c => c.BaseAddress = new Uri(apiBaseUrl));

builder.Services.AddScoped(sp =>
{
    var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(ApiClientService));
    var tokenService = sp.GetRequiredService<ClientCredentialsTokenService>();
    return new ApiClientService(http, tokenService);
});

WebApplication app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseAuthorization();
app.MapControllers();

app.Run("http://localhost:5001");
