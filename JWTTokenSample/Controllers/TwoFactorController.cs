using EmailService;
using JWTTokenSample.Entities.Models;
using JWTTokenSample.Services;
using JWTTokenSample.Shared.DTO.Auth;
using JWTTokenSample.Shared.DTO.TwoFactor;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace JWTTokenSample.Controllers
{
	/// <summary>
	/// 
	/// </summary>
	[Route("api/[controller]")]
    [ApiController]
    public class TwoFactorController : ControllerBase
	{
		private readonly UserManager<User> _userManager;
		private readonly IServiceManager _service;
		private readonly IEmailSender _emailSender;
		private readonly UrlEncoder _urlEncoder;

		/// <summary>
		/// 
		/// </summary>
		/// <param name="userManager"></param>
		/// <param name="service"></param>
		/// <param name="emailSender"></param>
		/// <param name="urlEncoder"></param>
		public TwoFactorController(UserManager<User> userManager,
			IServiceManager service,
			IEmailSender emailSender,
			UrlEncoder urlEncoder)
		{
			_userManager = userManager;
			_service = service;
			_emailSender = emailSender;
			_urlEncoder = urlEncoder;
		}

		/// <summary>
		/// Email [1] : 2단계 인증 활성와 이메일 인증
		/// </summary>
		/// <returns></returns>
		[HttpGet("Email/Init")]
		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		public async Task<IActionResult> InitEmail()
		{
			var userName = User.FindFirst(ClaimTypes.Name)?.Value;
			if (userName == null)
			{
				return null;
			}

			var user = await _userManager.FindByNameAsync(userName);

			if (user == null)
			{
				return null;
			}

			//토큰 생성
			var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

			var emailContent = $@"
			<p>2단계 인증 활성화</p>			
			<p> 
				입력 토큰 : {token}
			</p>";

			//메일 구조 생성
			var message = new Message(new string[] { user.Email }, "2단계 인증 활성화",
				emailContent, null);

			//메일 발송
			await _emailSender.SendEmailAsync(message);

			return Ok();
		}


		/// <summary>
		/// Email [2] : 이메일 인증으로 2단계 인증 활성화
		/// </summary>
		/// <param name="verifyAuthenticator"></param>
		/// <returns></returns>
		[HttpPost("Email/Setup")]
		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		public async Task<IActionResult> SetupEmail([FromBody] EmailTwoFactorDto verifyAuthenticator)
		{
			
			if (!ModelState.IsValid)
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});

			//email로 유저 찾기
			var user = await _userManager.FindByEmailAsync(verifyAuthenticator.Email);
			if (user == null)
			{
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});
			}

			//유저의 인증 방식과 토큰 이 일치하는지 확인
			var validVerification = await _userManager.VerifyTwoFactorTokenAsync(user,
				 TokenOptions.DefaultEmailProvider, verifyAuthenticator.TwoFactorToken);

			if (!validVerification)
			{
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Token Verification"
				});
			}

			await _userManager.SetTwoFactorEnabledAsync(user, true);

			return Ok();
		}


		/// <summary>
		/// 구글 OTP SETUP (초기 OTP 설정을 위한 QRCODE 만들 내용)
		/// </summary>
		/// <returns></returns>
		[HttpGet("OTP/Init")]
		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		public async Task<GoogleTwoFactorSetupDto?> InitAuthenticator()
		{
			var userName = User.FindFirst(ClaimTypes.Name)?.Value;
			if (userName == null) {
				return null;
			}

			var user = await _userManager.FindByNameAsync(userName);

			if(user == null)
            {
				return null;
			}

			var authenticatorDetails = await GetAuthenticatorDetailsAsync(user);

			return authenticatorDetails;
		}

		/// <summary>
		/// OTP [1] : 초기 OTP Value 만들기
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		private async Task<GoogleTwoFactorSetupDto> GetAuthenticatorDetailsAsync(User user)
		{
			// Load the authenticator key & QR code URI to display on the form
			var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
			if (string.IsNullOrEmpty(unformattedKey))
			{
				await _userManager.ResetAuthenticatorKeyAsync(user);
				unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
			}

			var email = await _userManager.GetEmailAsync(user);

			return new GoogleTwoFactorSetupDto
			{
				SharedKey = FormatKey(unformattedKey), //지정된 user에 대한 인증자 키를 가져옵니다.
				AuthenticatorUri = GenerateQrCodeUri(email, unformattedKey) //QRCode URL
			};
		}

		/// <summary>
		/// OTP [2] : OTP 사용 승인 처리 Login/OTP/Init에서 처리된 값 확인용(복구 코드전달함)
		/// </summary>
		/// <param name="verifyAuthenticator"></param>
		/// <returns></returns>
		[HttpPost("OTP/Setup")]
		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		public async Task<IActionResult> SetupAuthenticator([FromBody] GoogleTwoFactorConfirmDto verifyAuthenticator)
		{
			var userName = User.FindFirst(ClaimTypes.Name)?.Value;
			if (userName == null)
			{
				return BadRequest("error");
			}

			var user = await _userManager.FindByNameAsync(userName);

			if (user == null)
			{
				return BadRequest("error");
			}

			if (!ModelState.IsValid || verifyAuthenticator == null || verifyAuthenticator.VerificationCode == null)
			{
				return BadRequest("error");
			}

			var verificationCode = verifyAuthenticator.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

			var is2FaTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
				user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

			if (!is2FaTokenValid)
			{
				return BadRequest("error");
			}

			await _userManager.SetTwoFactorEnabledAsync(user, true);


			if (await _userManager.CountRecoveryCodesAsync(user) != 0)
			{
				return Ok();
			}

			var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

			return Ok(recoveryCodes);
		}


		/// <summary>
		/// 지정된 user에 대한 인증자 키를 가져옵니다.
		/// </summary>
		/// <param name="unformattedKey"></param>
		/// <returns></returns>
		private string FormatKey(string unformattedKey)
		{
			var result = new StringBuilder();
			int currentPosition = 0;
			while (currentPosition + 4 < unformattedKey.Length)
			{
				result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
				currentPosition += 4;
			}
			if (currentPosition < unformattedKey.Length)
			{
				result.Append(unformattedKey.Substring(currentPosition));
			}

			return result.ToString().ToLowerInvariant();
		}

		/// <summary>
		/// OTP 설정 인증 URL 만들기
		/// </summary>
		/// <param name="email"></param>
		/// <param name="unformattedKey"></param>
		/// <returns></returns>
		private string GenerateQrCodeUri(string email, string unformattedKey)
		{
			const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

			return string.Format(
				AuthenticatorUriFormat,
				_urlEncoder.Encode("Changzakso"),
				_urlEncoder.Encode(email),
				unformattedKey);
		}
	}
}
