using JWTTokenSample.Entities.Models;
using JWTTokenSample.Services;
using JWTTokenSample.Shared.DTO;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTTokenSample.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly IServiceManager _service;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userManager"></param>
        /// <param name="service"></param>
        public TokenController(UserManager<User> userManager,
            IServiceManager service)
        {
            _userManager = userManager;
            _service = service;
        }

        /// <summary>
        /// 리프레시 토큰을 통해 토큰 재발급
        /// </summary>
        /// <param name="tokenDto"></param>
        /// <returns></returns>
        /// <exception cref="UnauthorizedAccessException"></exception>
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenDto tokenDto)
        {
            if (tokenDto == null || tokenDto.Token == null)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsAuthSuccessful = false,
                    ErrorMessage = "Invalid client request"
                });
            }

            //기존 토큰 으로 정보 획득 
            var principal = _service.AccountService
                .GetPrincipalFromExpiredToken(tokenDto.Token);

            //정보값이 존재하는지
            if (principal == null || principal.Identity == null)
            {
                throw new UnauthorizedAccessException();
            }

            //유저 이름(여기서는 이메일이다)
            var username = principal.Identity.Name;

            //유저 찾기
            var user = await _userManager.FindByEmailAsync(username);

            //유저의 refresh 토큰이 body에 refresh 토큰과 같은지 비교
            // 만료 기간이 남아 있는지 확인
            if (user.RefreshToken != tokenDto.RefreshToken ||
                user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsAuthSuccessful = false,
                    ErrorMessage = "Invalid client request"
                });
            }

            //정상 이라면 토큰 재발급 , 리프레시 토큰 재발급
            var token = await _service.AccountService.GetToken(user);
            user.RefreshToken = _service.AccountService.GenerateRefreshToken();

            //업데이트 정보 저장
            await _userManager.UpdateAsync(user);

            //결과값 리턴
            return Ok(new AuthResponseDto
            {
                Token = token,
                RefreshToken = user.RefreshToken,
                IsAuthSuccessful = true
            });
        }
    }
}
