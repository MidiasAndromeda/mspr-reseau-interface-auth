using Microsoft.AspNetCore.Hosting.Internal;
using Mspr.Reseau.Auth.Dto;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Web;

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

        /// <summary>
        /// Connecte l'utilisateur
        /// </summary>
        /// <param name="email"></param>
        /// <param name="password"></param>
        /// <param name="ipAdress"></param>
        /// <param name="browserValue"></param>
        /// <returns></returns>
        public UserDto getUser(string email, string password, string ipAdress, string browserValue)
        {
            UserDto userDto = new UserDto();
            Boolean newIp = false;
            Boolean newBrowser = false;

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
                userDto.NbEssais += 1;

                //CHECK IP
                if (!userDto.AdressesIp.Contains(ipAdress)){
                    newIp = true;
                    userDto.AdressesIp.Add(ipAdress);
                    DirEntry.Properties["userIps"].Clear();
                    foreach (string ip in userDto.AdressesIp)
                    {
                        DirEntry.Properties["userIps"].Add(ip);
                    }
                }

                //CHECK BROWSER 
                if (!userDto.NavigatorInfos.Contains(browserValue))
                {
                    newBrowser = true;
                    userDto.NavigatorInfos.Add(browserValue);

                    DirEntry.Properties["browserInfos"].Clear();
                    foreach (string browser in userDto.NavigatorInfos)
                    {
                        DirEntry.Properties["browserInfos"].Add(browser);
                    }
                }

                if(DirEntry.Properties["authTry"].Count > 0)
                {
                    DirEntry.Properties["authTry"][0] = userDto.NbEssais;
                }
                else
                {
                    DirEntry.Properties["authTry"].Add(userDto.NbEssais);
                }
                DirEntry.CommitChanges();

                if (userDto.NbEssais >= 3)
                {
                    userDto.EstBloque = true;
                    DirEntry.CommitChanges();
                }

                if (newIp)
                {
                    //MEME PAYS ?? 
                    if (GetCountryFromIp(userDto.AdressesIp[0]) == GetCountryFromIp(ipAdress))
                    {
                        // ENVOI MAIL POUR PREVENIR USER
                        EnvoiMailIp(userDto);

                        DirEntry.CommitChanges();
                    }
                    else //SINON -> EST BLOQUE TRUE
                    {
                        userDto.EstBloque = true;
                        DirEntry.CommitChanges();
                    }
                }

                if (newBrowser)
                {
                    //SEND MAIL ET BLOCK ACCOUNT
                    userDto.EstBloque = true;
                    DirEntry.CommitChanges();
                }



                if (GenerateSHA512String(password) != userDto.Password)
                {
                    throw new Exception("Bad password");
                }

                //CHECK BLOCKED ACCOUNT
                if (userDto.EstBloque)
                {
                    //SEND MAIL TO DEBLOCK
                    EnvoiMailBloque(userDto);
                    throw new Exception("This user is blocked. Verify your email.");
                }

                userDto.EstBloque = false;
                userDto.NbEssais = 0;
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
                //On remplit ses infos
                using (DirectoryEntry user = directoryEntry.Children.Add("cn=" + userDto.Nom, "user"))
                {
                    user.Properties["SAMAccountName"].Add(userDto.Email);
                    user.Properties["name"].Add(userDto.Nom);
                    user.Properties["mail"].Add(userDto.Email);
                    user.Properties["userAccountBlocked"].Add(userDto.EstBloque);
                    user.Properties["authTry"].Add(userDto.NbEssais);

                    foreach (string infos in userDto.NavigatorInfos)
                    {
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
            
            
        }

        /// <summary>
        /// Créé une connexion à l'AD
        /// </summary>
        /// <returns></returns>
        private DirectoryEntry getActiveDirectory()
        {
            return new DirectoryEntry("LDAP://127.0.0.1", "Administrateur", "msprPortal2020@");
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

            //nombre essaies connexion
            if (entry.Properties["authTry"].Count > 0)
            {
                user.NbEssais = Convert.ToInt32(entry.Properties["authTry"].Value);
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

        private string GetCountryFromIp(string ip)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://ipapi.co/"+ip+"/country/");
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();

            var reader = new System.IO.StreamReader(response.GetResponseStream(), ASCIIEncoding.ASCII);
            return reader.ReadToEnd();
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

        public static void EnvoiMailBloque(UserDto user)
        {
            string to = user.Email;
            string from = "portail.chatelet@pierre-noble.com";
            MailMessage message = new MailMessage(from, to);
            message.Subject = "Débloquer votre compte.";
            message.Body = @"Cliquer <a href='www.portail.chatelet.pierre-noble.com/" + user.Nom + "'> ici </a> pour débloquer votre compte.";
            

            try
            {
                SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
                client.Credentials = new NetworkCredential("antoine.plagnol@gmail.com", "Ferney7166");
                client.UseDefaultCredentials = false;
                client.EnableSsl = true;
                // Credentials are necessary if the server requires the client
                // to authenticate before it will send email on the client's behalf.
                client.Send(message);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public static void EnvoiMailIp(UserDto user)
        {
            string to = user.Email;
            string from = "portail.chatelet@pierre-noble.com";
            MailMessage message = new MailMessage(from, to);
            message.Subject = "Débloquer votre compte.";
            message.Body = @"Cliquer <a href='www.portail.chatelet.pierre-noble.com/" + user.Nom + "'> ici </a> pour débloquer votre compte.";

            try
            {
                SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
                client.Credentials = new NetworkCredential("antoine.plagnol@gmail.com", "Ferney7166");
                client.EnableSsl = true;
                client.Send(message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erreur lors de l'envoi de mail",
                    ex.ToString());
            }
        }
    }
   

}
