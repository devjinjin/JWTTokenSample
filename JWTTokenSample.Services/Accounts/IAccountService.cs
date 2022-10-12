using JWTTokenSample.Entities.Models;
using System.Security.Claims;

namespace JWTTokenSample.Services.Authentications
{
    public interface IAccountService
    {
        Task<string> GetToken(User user);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
