using JWTTokenSample.Entities.Models;
using System.Security.Claims;

namespace JWTTokenSample.Services.Authentications
{
    public interface IAccountService
    {
        /// <summary>
        /// jwt 토큰 생성
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        Task<string> GetToken(User user);

        /// <summary>
        /// 리프레시 토큰 생성
        /// </summary>
        /// <returns></returns>
        string GenerateRefreshToken();

        /// <summary>
        /// 기존 토큰을 통해 정보 획득
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
