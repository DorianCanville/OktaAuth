using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

var builder = WebApplication.CreateBuilder(args);

// 1. Ajouter les services
builder.Services.AddControllers();

// Récupérer la config
var authority = builder.Configuration["Okta:Authority"];
var audience = builder.Configuration["Okta:Audience"];

// Authentication / JWT configuration with stricter validation
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.Authority = authority;
    options.Audience = audience;

    // Environnements : n'exposer les détails d'erreurs qu'en dev
    options.IncludeErrorDetails = builder.Environment.IsDevelopment();

    // Exiger HTTPS pour la métadonnée si on n'est pas en dev
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

    // Ne pas sauvegarder automatiquement le token côté serveur
    options.SaveToken = false;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
        ValidateIssuer = true,
        ValidIssuer = authority?.TrimEnd('/'),
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };
});

var app = builder.Build();

// Sécurité transport : HSTS et redirection HTTPS en production
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseAuthentication(); // <-- VITAL : Vérifie "Qui est-ce ?"
app.UseAuthorization();  // <-- VITAL : Vérifie "A-t-il le droit ?"

app.MapControllers();

// NOTE: En développement local vous pouvez rester en HTTP ; en production, configurez une URL HTTPS et certificats
app.Run("http://localhost:5000");