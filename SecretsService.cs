using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using GitHubSecrets.Application.Common.Options.Mdw;
using GitHubSecrets.Application.CQ.Teradata.Dtos;
using GitHubSecrets.Application.Interfaces;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace GitHubSecrets.Infrastructure.Services
{
    public class SecretsService : ISecretsService
    {
        private readonly SecretsOptions _secretsOptions;
        private readonly HttpClient _httpClient;
        private readonly ILogger<SecretsService> _logger;

        public SecretsService(IOptions<SecretsOptions> options, IHttpClientFactory httpClientFactory,
            ILogger<SecretsService> logger)
        {
            _secretsOptions = options.Value ??
                throw new ArgumentNullException(nameof(options));
            _httpClient = httpClientFactory.CreateClient();
            _logger = logger;
        }

        public async Task<bool> UpdateValue(string secretName, string secretValue)
        {
            var publicKeys = await GetSecretsPublicKeyAsync() ?? throw new ArgumentNullException("Failed to get public keys for github secrets.");

            var secretValuePassword = Encoding.UTF8.GetBytes(secretValue);
            var publicKey = Convert.FromBase64String(publicKeys.Key);
            var sealedPublicKeyForPassword = Sodium.SealedPublicKeyBox.Create(secretValuePassword, publicKey);

            var request = CreateHttpRequestMessage(HttpMethod.Put, $"{_secretsOptions.SecretsUrl}/{secretName}");

            request.Content = new StringContent(JsonSerializer.Serialize(
               new
               {
                   encrypted_value = Convert.ToBase64String(sealedPublicKeyForPassword),
                   key_id = publicKeys.KeyId
               }), Encoding.UTF8, "application/json");

            var response = await _httpClient.SendAsync(request);

            return response.StatusCode == HttpStatusCode.NoContent;
        }

        private HttpRequestMessage CreateHttpRequestMessage(HttpMethod method, string url)
        {
            var httpRequestMessage = new HttpRequestMessage(method, url);

            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(scheme: "Basic",
                parameter: Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_secretsOptions.User}:{_secretsOptions.AccessToken}"))
           );

            httpRequestMessage.Headers.Add("User-Agent", "sva");

            return httpRequestMessage;
        }

        private async Task<GitHubPublicKey> GetSecretsPublicKeyAsync()
        {
            var request = CreateHttpRequestMessage(HttpMethod.Get, _secretsOptions.PublicKeyUrl);

            var responsePublicKey = await _httpClient.SendAsync(request);
            var publicKeyReponse = await responsePublicKey.Content.ReadAsStringAsync();

            return JsonSerializer.Deserialize<GitHubPublicKey>(publicKeyReponse);
        }
    }
}
