using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Mspr.Reseau.Auth.AdServices;
using Mspr.Reseau.Auth.Api.Services.Interfaces;
using Mspr.Reseau.Auth.Dto;
using System;
using System.Collections.Generic;

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
                StringValues browserValue;
                HttpContext.Request.GetTypedHeaders().Headers.TryGetValue("User-Agent", out browserValue);
                string ipAddress = HttpContext.GetServerVariable("REMOTE_ADDR");
                var user = _authService.Authenticate(model.Username, model.Password, ipAddress, browserValue.ToString());
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
            try
            {
                AdServices.AdServices service = new AdServices.AdServices();
                string final = "";
                List<UserDto> users = service.getListOfUser();
                foreach (UserDto user in users)
                {
                    final += user.Nom + " ";
                }
                return Ok(final);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("debloc")]
        public IActionResult No([FromQuery]DebloquerDto parameters)
        {
            AdServices.AdServices service = new AdServices.AdServices();
            try
            {
                service.deblocUser(parameters.Mail);
                return Ok("user debloqued");

            }
            catch(Exception ex)
            {
                return BadRequest(ex.Message); 
            }
        }

    }
}
