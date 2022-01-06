using System.Threading.Tasks;

namespace GitHubSecrets.Application.Interfaces
{
    public interface ISecretsService
    {
        Task<bool> UpdateValue(string secretName, string secretValue);
    }
}