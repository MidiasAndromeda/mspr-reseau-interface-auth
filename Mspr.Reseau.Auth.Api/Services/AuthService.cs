using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Mspr.Reseau.Auth.Api.Helpers;
using Mspr.Reseau.Auth.Api.Services.Interfaces;
using Mspr.Reseau.Auth.Dto;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;

namespace Mspr.Reseau.Auth.Api.Services
{
    public class AuthService: IAuthService
    {
        private readonly AppSettings _appSettings;
        private AdServices.AdServices _adServices;

        public AuthService(IOptions<AppSettings> appSettings)
        {
            _appSettings = appSettings.Value;
            _adServices = new AdServices.AdServices();
        }

        public UserDto Authenticate([FromBody]string username, [FromBody]string password, string ipAdress, string browserValue)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentNullException("Username", "Username is required.");

            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("Password", "Password is required.");

            // GET USER FROM ACTIVE DIRECTORY
            UserDto user = _adServices.getUser(username, password, ipAdress, browserValue);

            //CHECK USER EXISTE
            if(user == new UserDto())
            {
                throw new AppException("This user account does not exist.");
            }

            // Have I been Pwned ?
            if (HaveIBeenPowned(username))
                throw new AppException("The email has been found in a powned credentials dictionnary. Please create a new account with a safe email.");

            if (HaveIBeenPowned(password))
                throw new AppException("The password has been found in a powned credentials dictionnary. Please make sure you change your password before you retry logging in.");

            

            return user;
        }
        private bool HaveIBeenPowned(string stringToTest)
        {
            bool result = false;

            using (SqlConnection connection = new SqlConnection("Server=WIN-OEUHH2MHVVK6;Database=Powned;User Id=powned;Password=password;"))
            {
                SqlCommand command = new SqlCommand("SELECT * FROM  Powned WHERE mail ='" + stringToTest + "' OR password ='" + stringToTest + "'", connection);
                command.Connection.Open();
                using (SqlDataReader reader = command.ExecuteReader())
                {
                    if (reader.HasRows)
                    {
                        result = true;
                    }
                }
            }

            return result;
        }

    }
}
