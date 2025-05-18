using Metrics.Models;

namespace Metrics.Services
{
    public interface IUserService
    {
        Task<User?> AuthenticateAsync(string username, string password);
    }
}
