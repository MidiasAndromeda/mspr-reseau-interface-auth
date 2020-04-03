using Mspr.Reseau.Auth.Dto;

namespace Mspr.Reseau.Auth.Api.Services.Interfaces
{
    public interface IAuthService
    {
        UserDto Authenticate(string username, string password);
    }
}
