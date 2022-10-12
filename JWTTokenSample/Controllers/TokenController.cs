using JWTTokenSample.Entities.Models;
using JWTTokenSample.Services;
using JWTTokenSample.Shared.DTO;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTTokenSample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
		private readonly UserManager<User> _userManager;
		private readonly IServiceManager _service;

		public TokenController(UserManager<User> userManager,
			IServiceManager service)
		{
			_userManager = userManager;
			_service = service;
		}

		[HttpPost("refresh")]
		public async Task<IActionResult> Refresh(
			[FromBody] RefreshTokenDto tokenDto)
		{
			if (tokenDto == null || tokenDto.Token == null) {
				return BadRequest(new AuthResponseDto
				{
					IsAuthSuccessful = false,
					ErrorMessage = "Invalid client request"
				});
			}

			var principal = _service.AccountService
				.GetPrincipalFromExpiredToken(tokenDto.Token);

			if (principal == null || principal.Identity == null) {
				throw new UnauthorizedAccessException();
			}

			var username = principal.Identity.Name;

			var user = await _userManager.FindByEmailAsync(username);
			if (user.RefreshToken != tokenDto.RefreshToken ||
				user.RefreshTokenExpiryTime <= DateTime.Now)
				return BadRequest(new AuthResponseDto
				{
					IsAuthSuccessful = false,
					ErrorMessage = "Invalid client request"
				});

			var token = await _service.AccountService.GetToken(user);
			user.RefreshToken = _service.AccountService.GenerateRefreshToken();

			await _userManager.UpdateAsync(user);

			return Ok(new AuthResponseDto
			{
				Token = token,
				RefreshToken = user.RefreshToken,
				IsAuthSuccessful = true
			});
		}
	}
}
