using IdentityModel.Client;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualBasic;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using TestKeycloak.Dtos;

namespace TestKeycloak.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;

        public AuthController(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetToken([FromBody] TokenRequestDto request)
        {
            var client = _httpClientFactory.CreateClient();

            var keycloakUrl = $"{_configuration["Keycloak:Url"]}/realms/{_configuration["Keycloak:Realm"]}/protocol/openid-connect/token";
            var clientId = _configuration["Keycloak:ClientId"]!;

            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("grant_type", "password"),
                new KeyValuePair<string, string>("username", request.username),
                new KeyValuePair<string, string>("password", request.password),
                new KeyValuePair<string, string>("scope", request.scope)
            });

            var response = await client.PostAsync(keycloakUrl, content);

            if(!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());
            }

            var tokenResponse = await response.Content.ReadAsStringAsync();

            var parsedJson = JsonConvert.DeserializeObject(tokenResponse);
            var prettyJson = JsonConvert.SerializeObject(parsedJson, Formatting.Indented);

            return Ok(prettyJson);
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterDto request)
        {
            var client = _httpClientFactory.CreateClient();

            var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = $"{_configuration["Keycloak:Url"]}/realms/{_configuration["Keycloak:Realm"]}/protocol/openid-connect/token",
                ClientId = _configuration["Keycloak:AdminClientId"]!, // e.g., "admin-api-client"
                ClientSecret = _configuration["Keycloak:AdminClientSecret"],
                Scope = "openid"
            });

            if (tokenResponse.IsError)
            {
                return StatusCode(500, $"Error retrieving admin access token: {tokenResponse.ErrorDescription}");
            }

            client.SetBearerToken(tokenResponse.AccessToken!);

            var userPayload = new
            {
                username = request.Username,
                email = request.Email,
                enabled = true,
                credentials = new[] { new { type = "password", value = request.Password, temporary = false } },
            };

            var response = await client.PostAsJsonAsync($"{_configuration["Keycloak:Url"]}/admin/realms/{_configuration["Keycloak:Realm"]}/users", userPayload);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                return StatusCode((int)response.StatusCode, errorContent);
            }

            return Ok("User registered successfully");
        }

        [HttpPost("validateToken")]
        public async Task<IActionResult> ValidateToken([FromBody] string token)
        {
            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await client.GetAsync($"{_configuration["Keycloak:Url"]}/realms/{_configuration["Keycloak:Realm"]}/protocol/openid-connect/userinfo");

            if (!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());
            }
            var tokenResponse = await response.Content.ReadAsStringAsync();

            var parsedJson = JsonConvert.DeserializeObject(tokenResponse);
            var prettyJson = JsonConvert.SerializeObject(parsedJson, Formatting.Indented);

            return Ok(prettyJson);
        }

        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto request)
        {
            var client = _httpClientFactory.CreateClient();
            var keycloakUrl = $"{_configuration["Keycloak:Url"]}/realms/{_configuration["Keycloak:Realm"]}/protocol/openid-connect/token";

            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", _configuration["Keycloak:ClientId"]!),
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("refresh_token", request.RefreshToken)
            });

            var response = await client.PostAsync(keycloakUrl, content);

            if (!response.IsSuccessStatusCode)
            {
                return StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());
            }
            var tokenResponse = await response.Content.ReadAsStringAsync();

            var parsedJson = JsonConvert.DeserializeObject(tokenResponse);
            var prettyJson = JsonConvert.SerializeObject(parsedJson, Formatting.Indented);

            return Ok(prettyJson);
        }

        [HttpPost("addRole")]
        public async Task<IActionResult> AddRoleToUser([FromBody] RoleAssignmentDto request)
        {
            var client = _httpClientFactory.CreateClient();
            var tokenResponse = await client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = $"{_configuration["Keycloak:Url"]}/realms/{_configuration["Keycloak:Realm"]}/protocol/openid-connect/token",
                ClientId = _configuration["Keycloak:AdminClientId"]!, // e.g., "admin-api-client"
                ClientSecret = _configuration["Keycloak:AdminClientSecret"],
                Scope = "openid"
            });

            if (tokenResponse.IsError)
            {
                return StatusCode(500, $"Error retrieving admin access token: {tokenResponse.ErrorDescription}");
            }

            client.SetBearerToken(tokenResponse.AccessToken!);

            var userId = await GetUserIdByUsername(client, request.Username);
            if (string.IsNullOrEmpty(userId)) return NotFound("User not found");

            //Get Role Information by Role Name
            var roleResponse = await client.GetAsync($"{_configuration["Keycloak:Url"]}/admin/realms/{_configuration["Keycloak:Realm"]}/roles/{request.RoleName}");
            if (!roleResponse.IsSuccessStatusCode)
            {
                return NotFound("Role not found");
            }
            var role = await roleResponse.Content.ReadFromJsonAsync<RoleRepresentation>();
            if (role == null)
            {
                return NotFound("Role not found");
            }


            var rolePayload = new[]
            {
                role 
            };

            var response = await client.PostAsJsonAsync($"{_configuration["Keycloak:Url"]}/admin/realms/{_configuration["Keycloak:Realm"]}/users/{userId}/role-mappings/realm", rolePayload);

            return response.IsSuccessStatusCode ? Ok("Role added to user") : StatusCode((int)response.StatusCode, await response.Content.ReadAsStringAsync());
        }


        private async Task<string> GetUserIdByUsername(HttpClient client, string username)
        {
            var requestUrl = $"{_configuration["Keycloak:Url"]}/admin/realms/{_configuration["Keycloak:Realm"]}/users?username={Uri.EscapeDataString(username)}";

            var response = await client.GetAsync(requestUrl);

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                var users = JsonConvert.DeserializeObject<List<dynamic>>(content);

                if (users != null && users.Count > 0)
                {
                    return users[0].id;
                }
            }
            else
            {
                var errorContent = await response.Content.ReadAsStringAsync();
            }

            return null;
        }


    }
}
