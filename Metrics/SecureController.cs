using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Metrics.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SecureController : ControllerBase
    {
        private readonly IContext _context;

        public SecureController(IContext context)
        {
            _context = context;
        }

        [Authorize]
        [HttpGet("data")]
        public IActionResult GetSecretData()
        {
            return Ok(new { message = "This is protected data", user = _context.UserName });
        }
    }
}
