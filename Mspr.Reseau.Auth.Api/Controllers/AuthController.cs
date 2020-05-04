using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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
            AdServices.AdServices service = new AdServices.AdServices();
            string final = "";
            List<UserDto> users = service.getListOfUser();
            foreach(UserDto user in users)
            {
                final += user.Nom + " ";
            }
            return Ok(final);

        }

        [HttpGet("test")]
        public IActionResult No()
        {
            AdServices.AdServices service = new AdServices.AdServices();
            try
            {
                /*
                UserDto user = new UserDto()
                {
                    Id = 1,
                    Nom = "UsernameUser5",
                    Password = "passwordUser",
                    Email = "antoine5@plagnol.com",
                    EstBloque = false,
                    NavigatorInfos = new List<string>(),
                    AdressesIp = new List<string>()
                };

                user.AdressesIp.Add("8.8.8.8");
                user.AdressesIp.Add("9.9.9.9");

                user.NavigatorInfos.Add("test1");
                user.NavigatorInfos.Add("test2");
                user.NavigatorInfos.Add("test3");

                service.addUser(user);
                */
                UserDto user = service.getUser("antoine5@plagnol.com", "passwordUffser");
                
                return Ok(user.Nom);
            }
            catch(Exception ex)
            {
                return BadRequest(ex.Message); 
            }
        }
    }
}
