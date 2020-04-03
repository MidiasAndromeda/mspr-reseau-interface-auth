using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Mspr.Reseau.Auth.Api.Helpers;
using Mspr.Reseau.Auth.Api.Services.Interfaces;
using Mspr.Reseau.Auth.Dto;
using System;

namespace Mspr.Reseau.Auth.Api.Services
{
    public class AuthService: IAuthService
    {
        private readonly AppSettings _appSettings;

        public AuthService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
        }

        public UserDto Authenticate([FromBody]string username, [FromBody]string password)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentNullException("Username", "Username is required.");

            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("Password", "Password is required.");

            // GET USER FROM POWERSHELL LIBRARY
            var user = new UserDto()
            {
                Id = 1,
                Nom = username,
                Password = password
            };

            return user;
        }
    }
}
