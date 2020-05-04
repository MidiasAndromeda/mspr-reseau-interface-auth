using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Mspr.Reseau.Auth.Api.Helpers;
using Mspr.Reseau.Auth.Api.Services.Interfaces;
using Mspr.Reseau.Auth.Dto;
using RestSharp;
using System;
using System.Collections.Generic;

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
            UserDto user = new UserDto()
            {
                Id = 1,
                Nom = username,
                Password = password
            };
            // Have I been Pwned ?
            if (HaveIBeenPowned(username))
                throw new AppException("The email has been found in a powned credentials dictionnary. Please create a new account with a safe email.");

            if (HaveIBeenPowned(password))
                throw new AppException("The password has been found in a powned credentials dictionnary. Please make sure you change your password before you retry logging in.");

            return user;
        }
        private bool HaveIBeenPowned(string stringToTest)
        {
            string hibpApiUrl = "https://haveibeenpwned.com/unifiedsearch/";

            // API call for username
            var client = new RestClient(hibpApiUrl);

            var request = new RestRequest(stringToTest, DataFormat.Json);

            // Get request
            var response = client.Get(request);

            // If the api returns something, the user has been powned, otherwise, it's safe
            return response != null ? true : false;
        }

    }
}
