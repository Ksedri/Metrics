using System.Security.Claims;

namespace Metrics
{
    public class Context : IContext
    {
        private readonly ClaimsPrincipal _user;

        public Context(IHttpContextAccessor httpContextAccessor)
        {
            _user = httpContextAccessor.HttpContext?.User ?? new ClaimsPrincipal();
        }

        public ClaimsPrincipal User => _user;

        public string UserId => _user.FindFirst("sub")?.Value;

        public string UserName => _user.Identity?.Name;

        public bool IsAuthenticated => _user.Identity?.IsAuthenticated ?? false;
    }

}
