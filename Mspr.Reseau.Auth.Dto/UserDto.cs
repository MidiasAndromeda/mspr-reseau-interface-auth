using System;
using System.Collections.Generic;

namespace Mspr.Reseau.Auth.Dto
{
    public class UserDto
    {
        public int Id { get; set; }
        public string Nom { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public Boolean EstBloque { get; set; }
        public List<string> NavigatorInfos { get; set; }
        public List<string> AdressesIp { get; set; }

        public UserDto()
        {
            NavigatorInfos = new List<string>();
            AdressesIp = new List<string>();
        }
    }
}
