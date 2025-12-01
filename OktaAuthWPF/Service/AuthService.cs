using Duende.IdentityModel.OidcClient;
using OktaAuthWPF.Service.Browser;

public class AuthService
{
    private readonly OidcClient _oidcClient;
    private string? _accessToken;
    private string? _refreshToken;

    public AuthService()
    {
        var options = new OidcClientOptions
        {
            Authority = "https://integrator-7886904.okta.com",
            ClientId = "0oaxwt7ysa4ncvmt7697",
            RedirectUri = "http://127.0.0.1:7890/callback",
            Scope = "openid profile email offline_access",
            Browser = new SystemBrowser(7890),
            DisablePushedAuthorization = true
        };

        _oidcClient = new OidcClient(options);
    }

    public async Task<LoginResult> Login()
    {
        var result = await _oidcClient.LoginAsync(new LoginRequest());
        if (!result.IsError)
        {
            _accessToken = result.AccessToken;
            _refreshToken = result.RefreshToken;
        }
        return result;
    }

    public async Task<bool> TryRefreshAsync()
    {
        if (string.IsNullOrEmpty(_refreshToken)) return false;

        var refreshResult = await _oidcClient.RefreshTokenAsync(_refreshToken);
        if (!refreshResult.IsError)
        {
            _accessToken = refreshResult.AccessToken;
            _refreshToken = refreshResult.RefreshToken ?? _refreshToken;
            return true;
        }

        // refresh failed -> forcer re-login
        _accessToken = null;
        _refreshToken = null;
        return false;
    }

    public string? GetAccessToken() => _accessToken;
}







//https://integrator-7886904.okta.com/oauth2/default/.well-known/openid-configuration
//response : 
//{
//    "issuer": "https://integrator-7886904.okta.com/oauth2/default",
//  "authorization_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/authorize",
//  "token_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/token",
//  "userinfo_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/userinfo",
//  "registration_endpoint": "https://integrator-7886904.okta.com/oauth2/v1/clients",
//  "jwks_uri": "https://integrator-7886904.okta.com/oauth2/default/v1/keys",
//  "response_types_supported": [
//    "code",
//    "id_token",
//    "code id_token",
//    "code token",
//    "id_token token",
//    "code id_token token"
//  ],
//  "response_modes_supported": [
//    "query",
//    "fragment",
//    "form_post",
//    "okta_post_message"
//  ],
//  "grant_types_supported": [
//    "authorization_code",
//    "implicit",
//    "refresh_token",
//    "password",
//    "urn:ietf:params:oauth:grant-type:device_code",
//    "urn:openid:params:grant-type:ciba",
//    "urn:okta:params:oauth:grant-type:otp",
//    "http://auth0.com/oauth/grant-type/mfa-otp",
//    "urn:okta:params:oauth:grant-type:oob",
//    "http://auth0.com/oauth/grant-type/mfa-oob"
//  ],
//  "subject_types_supported": [
//    "public"
//  ],
//  "id_token_signing_alg_values_supported": [
//    "RS256"
//  ],
//  "scopes_supported": [
//    "openid",
//    "profile",
//    "email",
//    "address",
//    "phone",
//    "offline_access",
//    "device_sso"
//  ],
//  "token_endpoint_auth_methods_supported": [
//    "client_secret_basic",
//    "client_secret_post",
//    "client_secret_jwt",
//    "private_key_jwt",
//    "none"
//  ],
//  "claims_supported": [
//    "iss",
//    "ver",
//    "sub",
//    "aud",
//    "iat",
//    "exp",
//    "jti",
//    "auth_time",
//    "amr",
//    "idp",
//    "nonce",
//    "name",
//    "nickname",
//    "preferred_username",
//    "given_name",
//    "middle_name",
//    "family_name",
//    "email",
//    "email_verified",
//    "profile",
//    "zoneinfo",
//    "locale",
//    "address",
//    "phone_number",
//    "picture",
//    "website",
//    "gender",
//    "birthdate",
//    "updated_at",
//    "at_hash",
//    "c_hash"
//  ],
//  "code_challenge_methods_supported": [
//    "S256"
//  ],
//  "introspection_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/introspect",
//  "introspection_endpoint_auth_methods_supported": [
//    "client_secret_basic",
//    "client_secret_post",
//    "client_secret_jwt",
//    "private_key_jwt",
//    "none"
//  ],
//  "revocation_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/revoke",
//  "revocation_endpoint_auth_methods_supported": [
//    "client_secret_basic",
//    "client_secret_post",
//    "client_secret_jwt",
//    "private_key_jwt",
//    "none"
//  ],
//  "end_session_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/logout",
//  "request_parameter_supported": true,
//  "request_object_signing_alg_values_supported": [
//    "HS256",
//    "HS384",
//    "HS512",
//    "RS256",
//    "RS384",
//    "RS512",
//    "ES256",
//    "ES384",
//    "ES512"
//  ],
//  "device_authorization_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/device/authorize",
//  "pushed_authorization_request_endpoint": "https://integrator-7886904.okta.com/oauth2/default/v1/par",
//  "backchannel_token_delivery_modes_supported": [
//    "poll"
//  ],
//  "backchannel_authentication_request_signing_alg_values_supported": [
//    "HS256",
//    "HS384",
//    "HS512",
//    "RS256",
//    "RS384",
//    "RS512",
//    "ES256",
//    "ES384",
//    "ES512"
//  ],
//  "dpop_signing_alg_values_supported": [
//    "RS256",
//    "RS384",
//    "RS512",
//    "ES256",
//    "ES384",
//    "ES512"
//  ]
//}