using System.Security.Claims;

namespace Metrics
{
    public interface IContext
    {
        string UserId { get; }
        string UserName { get; }
        bool IsAuthenticated { get; }
        ClaimsPrincipal User { get; }
    }

}
