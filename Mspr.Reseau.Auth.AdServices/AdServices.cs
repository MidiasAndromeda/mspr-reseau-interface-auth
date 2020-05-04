using Mspr.Reseau.Auth.Dto;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography;
using System.Text;

namespace Mspr.Reseau.Auth.AdServices
{
    public class AdServices
    {

        /// <summary>
        /// Récupère la liste d'utilisateur de l'AD
        /// </summary>
        /// <returns></returns>
        public List<UserDto> getListOfUser()
        {
            //On créé la liste d'utilisateur a return
            List<UserDto> users = new List<UserDto>();

            //On se connecte a l'AD avec le compte administrateur
            DirectoryEntry directoryEntry = getActiveDirectory();

            //On crée l'objet qui va rechercher dans l'AD
            DirectorySearcher searcher = new DirectorySearcher(directoryEntry);

            //On filtre par utilisateur
            searcher.Filter = "(objectClass=user)";

            //Info user des utilisateurs
            DirectoryEntry DirEntry = null;

            //On parcourt les users et on fait remplit la liste
            foreach (SearchResult result in searcher.FindAll())
            {
                DirEntry = result.GetDirectoryEntry();                
                users.Add(fillUserWithEntryData(DirEntry));
            }
            return users;
        }

        public UserDto getUser(string email, string password)
        {
            UserDto userDto = new UserDto();

            DirectoryEntry directoryEntry = getActiveDirectory();

            DirectorySearcher searcher = new DirectorySearcher(directoryEntry);
            searcher.Filter = "(&(objectClass=user)";
            searcher.Filter += "(SAMAccountName="+ email + "))";
            //Info user des utilisateurs
            DirectoryEntry DirEntry = null;

            foreach (SearchResult result in searcher.FindAll())
            {
                DirEntry = result.GetDirectoryEntry();
                userDto = (fillUserWithEntryData(DirEntry));
            }

            if(GenerateSHA512String(password) != userDto.Password)
            {
                throw new Exception("Bad password");
            }


            return userDto;
        }

        /// <summary>
        /// Ajoute un utilisateur a l'AD
        /// </summary>
        /// <param name="userDto"></param>
        public void addUser(UserDto userDto)
        {
            DirectoryEntry directoryEntry = getActiveDirectory();


            //Création de l'utilisateur
            DirectoryEntry user = directoryEntry.Children.Add("cn=" + userDto.Nom, "user");
            //On remplit ses infos
            user.Properties["SAMAccountName"].Add(userDto.Email);
            user.Properties["name"].Add(userDto.Nom);
            user.Properties["mail"].Add(userDto.Email);
            user.Properties["userAccountBlocked"].Add(userDto.EstBloque);
            foreach (string infos in userDto.NavigatorInfos){
                user.Properties["browserInfos"].Add(infos);
            }

            foreach (string ip in userDto.AdressesIp)
            {
                user.Properties["userIps"].Add(ip);
            }


            user.Properties["userCustomPassword"].Add(GenerateSHA512String(userDto.Password));

            // On envoie les modifications au serveur
            user.CommitChanges();
        }



        /// <summary>
        /// Créé une connexion à l'AD
        /// </summary>
        /// <returns></returns>
        private DirectoryEntry getActiveDirectory()
        {
            return new DirectoryEntry("LDAP://82.251.242.183", "Administrateur", "msprPortal2020@");
        }


        /// <summary>
        /// On créé un objet user via les information de l'AD
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        private UserDto fillUserWithEntryData(DirectoryEntry entry)
        {
            UserDto user = new UserDto();

            //Son nom
            if (entry.Properties["name"].Count > 0)
            {
                user.Nom = entry.Properties["name"].Value.ToString();
            }

            //Son password
            if (entry.Properties["userCustomPassword"].Count > 0)
            {
                user.Password = entry.Properties["userCustomPassword"].Value.ToString();
            }

            //Son mail
            if (entry.Properties["mail"].Count > 0)
            {
                user.Email = entry.Properties["mail"].Value.ToString();
            }

            //Est bloqué
            if (entry.Properties["userAccountBlocked"].Count > 0)
            {
                user.EstBloque = Convert.ToBoolean(entry.Properties["userAccountBlocked"][0]);
            }

            //Ses navigateurs
            if (entry.Properties["browserInfos"].Count > 0)
            {
                foreach (string value in entry.Properties["browserInfos"])
                {
                    user.NavigatorInfos.Add(value);
                }
                
            }

            //Ses IPS
            if (entry.Properties["userIps"].Count > 0)
            {
                foreach (string value in entry.Properties["userIps"])
                {
                    user.AdressesIp.Add(value);
                }
            }

            return user;

        }

        public static string GenerateSHA512String(string inputString)
        {
            SHA512 sha512 = SHA512Managed.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(inputString);
            byte[] hash = sha512.ComputeHash(bytes);
            return GetStringFromHash(hash);
        }
        private static string GetStringFromHash(byte[] hash)
        {
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                result.Append(hash[i].ToString("X2"));
            }
            return result.ToString();
        }
    }
   

}
