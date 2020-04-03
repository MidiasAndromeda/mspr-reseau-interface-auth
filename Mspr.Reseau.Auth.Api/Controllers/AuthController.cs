using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Mspr.Reseau.Auth.Api.Services.Interfaces;
using Mspr.Reseau.Auth.Dto;
using System;

namespace Mspr.Reseau.Auth.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost]
        public IActionResult Authenticate([FromBody]AuthenticationDto model)
        {
            try
            {
                var user = _authService.Authenticate(model.Username, model.Password);
                return Ok(user);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpGet]
        public IActionResult Yes()
        {
            return Ok("oui");
        }
    }
}
