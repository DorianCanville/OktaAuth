using Duende.IdentityModel.OidcClient;
using Duende.IdentityModel.OidcClient.Results;
using OktaAuthWPF.Service;
using OktaAuthWPF.Service.Browser;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;

public class AuthService
{
    private readonly OidcClient _oidcClient;
    private string? _accessToken;
    private string? _refreshToken;

    public string? GetAccessToken() => _accessToken;

    private UserContext _userContext;

    // Target name used in Windows Credential Manager   
    private const string CredentialTarget = "OktaAuthWPF_RefreshToken";

    public AuthService(UserContext userContext)
    {

        _userContext = userContext;

        OidcClientOptions options = new OidcClientOptions
        {
            Authority = "https://integrator-7886904.okta.com",
            ClientId = "0oaxwt7ysa4ncvmt7697",
            RedirectUri = "http://127.0.0.1:7890/callback",
            Scope = "openid profile email offline_access",
            Browser = new SystemBrowser(7890),
            DisablePushedAuthorization = true
        };

        _oidcClient = new OidcClient(options);

        // Try to load a previously stored refresh token from Credential Manager
        try
        {
            _refreshToken = LoadRefreshTokenFromCredentialManager();
        }
        catch (Exception ex)
        {
            //Log.Warn("CredentialManager read failed", ex);
            // Ignore any errors when reading credentials; treat as no token
            _refreshToken = null;
        }
    }


    public async Task<bool> EnsureAuthenticatedAsync()
    {
        // Tentative silencieuse
        if (await TryRefreshAsync())
        {
            return true;
        }

        // Sinon, affichage login Okta
        LoginResult loginResult = await Login();

        //_userContext.SetUser(new CurrentUserInfo()
        //{
        //    Email = loginResult.User.Identity.em
        //})
        await GetUserInfoAsync();

        return !loginResult.IsError;
    }

    public async Task<bool> GetUserInfoAsync()
    {
        if (string.IsNullOrEmpty(_accessToken))
            throw new InvalidOperationException("Not authenticated");

        using HttpClient http = new HttpClient();
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _accessToken);

        HttpResponseMessage response = await http.GetAsync(
            "https://integrator-7886904.okta.com/oauth2/default/v1/userinfo"); // besoin de https://integrator-7886904.okta.com/oauth2/default pour avoir la même base de connection

        //response.EnsureSuccessStatusCode();
        string content = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Userinfo failed: {(int)response.StatusCode} {response.ReasonPhrase}: {content}");
        string json = await response.Content.ReadAsStringAsync();

        return true;

        //return JsonSerializer.Deserialize<UserInfo>(json)!;
    }


    public async Task<LoginResult> Login()
    {
        LoginResult result = await _oidcClient.LoginAsync(new LoginRequest());
        if (!result.IsError)
        {
            _accessToken = result.AccessToken;
            _refreshToken = result.RefreshToken;

            // Persist the refresh token securely in Windows Credential Manager
            if (!string.IsNullOrEmpty(_refreshToken))
            {
                try
                {
                    SaveRefreshTokenToCredentialManager(_refreshToken);
                }
                catch (Exception ex)
                {
                    //Log.Warn("CredentialManager write failed", ex);
                }
            }
        }
        return result;
    }

    public async Task<bool> TryRefreshAsync()
    {
        // If we don't have a token in memory, try to load from Credential Manager
        if (string.IsNullOrEmpty(_refreshToken))
        {
            try
            {
                _refreshToken = LoadRefreshTokenFromCredentialManager();
            }
            catch
            {
                _refreshToken = null;
            }
        }

        if (string.IsNullOrEmpty(_refreshToken)) return false;

        RefreshTokenResult refreshResult = await _oidcClient.RefreshTokenAsync(_refreshToken); //TODO regarder pour changer de refresh à chaque demande
        if (!refreshResult.IsError)
        {
            _accessToken = refreshResult.AccessToken;
            _refreshToken = refreshResult.RefreshToken ?? _refreshToken;

            // Update stored refresh token if it changed
            if (!string.IsNullOrEmpty(_refreshToken))
            {
                try
                {
                    SaveRefreshTokenToCredentialManager(_refreshToken);
                }
                catch (Exception ex)
                {
                    //Log.Warn("CredentialManager read failed", ex);
                }
            }

            return true;
        }

        // refresh failed -> forcer re-login and remove stored token
        _accessToken = null;
        _refreshToken = null;
        try
        {
            DeleteRefreshTokenFromCredentialManager();
        }
        catch
        {
            // ignore
        }
        return false;
    }


    // ---------------------- Credential Manager helpers ----------------------

    private void SaveRefreshTokenToCredentialManager(string token)
    {
        byte[] blob = Encoding.Unicode.GetBytes(token);

        CREDENTIAL credential = new CREDENTIAL
        {
            Type = CRED_TYPE.GENERIC,
            TargetName = CredentialTarget,
            CredentialBlobSize = (uint)blob.Length,
            Persist = CRED_PERSIST.LOCAL_MACHINE,
            AttributeCount = 0,
            UserName = Environment.UserName
        };

        // allocate unmanaged memory for the blob
        credential.CredentialBlob = Marshal.AllocCoTaskMem(blob.Length);
        Marshal.Copy(blob, 0, credential.CredentialBlob, blob.Length);

        bool written = CredWrite(ref credential, 0);

        // free allocated memory
        Marshal.FreeCoTaskMem(credential.CredentialBlob);

        if (!written)
        {
            int err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"CredWrite failed with error {err}");
        }
    }

    private string? LoadRefreshTokenFromCredentialManager()
    {
        if (!CredRead(CredentialTarget, CRED_TYPE.GENERIC, 0, out nint credPtr) || credPtr == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            // If not found, return null
            if (err == 1168 || err == 2) // ERROR_NOT_FOUND / ERROR_FILE_NOT_FOUND
                return null;
            throw new InvalidOperationException($"CredRead failed with error {err}");
        }

        try
        {
            CREDENTIAL credential = Marshal.PtrToStructure<CREDENTIAL>(credPtr);
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
                return null;

            byte[] blob = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, blob, 0, (int)credential.CredentialBlobSize);
            return Encoding.Unicode.GetString(blob).TrimEnd('\0');
        }
        finally
        {
            CredFree(credPtr);
        }
    }

    private void DeleteRefreshTokenFromCredentialManager()
    {
        bool deleted = CredDelete(CredentialTarget, CRED_TYPE.GENERIC, 0);
        if (!deleted)
        {
            int err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"CredDelete failed with error {err}");
        }
    }

    // P/Invoke definitions and structures
    private enum CRED_PERSIST : uint
    {
        SESSION = 1,
        LOCAL_MACHINE = 2,
        ENTERPRISE = 3
    }

    private enum CRED_TYPE : uint
    {
        GENERIC = 1,
        DOMAIN_PASSWORD = 2,
        DOMAIN_CERTIFICATE = 3,
        DOMAIN_VISIBLE_PASSWORD = 4,
        GENERIC_CERTIFICATE = 5,
        DOMAIN_EXTENDED = 6,
        MAXIMUM = 7
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public CRED_TYPE Type;
        public string TargetName;
        public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public CRED_PERSIST Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, CRED_TYPE type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite([In] ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CredFree([In] IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredDelete(string target, CRED_TYPE type, int flags);
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