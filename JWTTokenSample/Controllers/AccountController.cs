using EmailService;
using JWTTokenSample.Entities.Models;
using JWTTokenSample.Services;
using JWTTokenSample.Shared.DTO;
using JWTTokenSample.Shared.DTO.Account;
using JWTTokenSample.Shared.DTO.Auth;
using JWTTokenSample.Shared.DTO.TwoFactor;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace JWTTokenSample.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
		private readonly UserManager<User> _userManager;
		private readonly IServiceManager _service;
		private readonly IEmailSender _emailSender;
		/// <summary>
		/// 
		/// </summary>
		/// <param name="userManager"></param>
		/// <param name="service"></param>
		/// <param name="emailSender"></param>
		public AccountController(
			UserManager<User> userManager,
			IServiceManager service,
			IEmailSender emailSender)
		{
			_userManager = userManager;
			_service = service;
			_emailSender = emailSender;
		}

		/// <summary>
		/// 회원가입 
		/// </summary>
		/// <remarks>
		/// 2단계 인증 위한 메일 전송 포함
		/// 인증방법 선택
		/// 
		/// </remarks>
		/// <param name="userForRegistrationDto"></param>
		/// <returns></returns>

		[HttpPost("Register")]
		public async Task<IActionResult> RegisterUser([FromBody] UserForRegistrationDto userForRegistrationDto)
		{
			//데이터가 비정상이다
			if (userForRegistrationDto == null || !ModelState.IsValid 
				|| userForRegistrationDto.Email == null
				|| userForRegistrationDto.ClientURI == null) {
				return BadRequest();
			}

			var user = new User
			{
				UserName = userForRegistrationDto.Email,
				Email = userForRegistrationDto.Email
			};

			var result = await _userManager.CreateAsync(user, userForRegistrationDto.Password);
			if (!result.Succeeded)
			{
				var errors = result.Errors.Select(e => e.Description);
				return BadRequest(new ResponseDto { Errors = errors });
			}

			//2단계인증 활성화 등록 초기는 False
			await _userManager.SetTwoFactorEnabledAsync(user, false);

			//이메일 인증 토큰 생성
			var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

			//링크를 만들기 위한 token & email 딕셔너리 생성
			var param = new Dictionary<string, string?>
			{
				{ "token", token },
				{ "email", userForRegistrationDto.Email  }
			};

			//userForRegistrationDto.ClientURI 외부에 노출할 필요는 없은 내부에서 생성해도 됨

			//이메일 확인 링크 주소 생성
			var callback = QueryHelpers.AddQueryString(userForRegistrationDto.ClientURI, param);

			//메일 내용
			// callback = 컨텐츠 내용임
			var emailContent = $@"
			<p>가입확인</p>			
			<p> 
				<a href='{callback}'>
					<input type='image' src='https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_92x30dp.png' border='0' alt='Submit' style='width: 50px;' />
				</a>
			</p>";

			//메일 문구 생성
			var message = new Message(new string[] { user.Email }, "이메일 가입 확인",
				emailContent, null);

			//메일 전송
			await _emailSender.SendEmailAsync(message);
				
			
			//유저 롤 권한 Viewer
			await _userManager.AddToRoleAsync(user, "User");

			//201 created 결과값
			return StatusCode(StatusCodes.Status201Created);
		}


		/// <summary>
		/// 회원가입 이메일 인증 확인용
		/// </summary>
		/// <remarks>
		/// Client통해 이메일/token 정보를 받은후
		/// 확인여부 전송 
		/// (클라이언트에서는 결과값에 따른 동작 추가 = 성공시 성공 페이지 또는 Redirect 처리해야함)
		/// confirmType = Email , GoogleOtp
		/// 기본값 Email
		/// </remarks>
		/// <param name="email"></param>
		/// <param name="token"></param>
		/// <returns></returns>
		[HttpGet("Register/Confirmation")]
		public async Task<IActionResult> EmailConfirmation([FromQuery] string email, [FromQuery] string token)
		{

			var user = await _userManager.FindByEmailAsync(email);
			if (user == null)
			{
				return BadRequest();
			}

			var confirmResult = await _userManager.ConfirmEmailAsync(user, token);
			if (!confirmResult.Succeeded)
			{
				return BadRequest();
			}

			return Ok();
		}

		/// <summary>
		/// 로그인 요청
		/// </summary>
		/// <remarks>
		/// 인증번호 메일로 전송 또는 인증 타입 전달
		/// </remarks>
		/// <param name="userForAuthenticationDto"></param>
		/// <returns></returns>
		[HttpPost("Login")]
		public async Task<IActionResult> Login(
			[FromBody] UserForAuthenticationDto userForAuthenticationDto)
		{
			//이메일로 유저 찾기
			var user = await _userManager.FindByNameAsync(userForAuthenticationDto.Email);

			if (user == null || userForAuthenticationDto.Email == null)
			{
				return Unauthorized(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});
			}

			if (!await _userManager.IsEmailConfirmedAsync(user))
				return Unauthorized(new AuthResponseDto
				{
					ErrorMessage = "이메일 확인이 아직 안되었습니다."
				});

			if (await _userManager.IsLockedOutAsync(user))
				return Unauthorized(new AuthResponseDto
				{
					ErrorMessage = "비활성화 계정입니다"
				});

			//비밀번호 확인
			if (!await _userManager.CheckPasswordAsync(user, userForAuthenticationDto.Password))
			{
				//비밀번호 확인 실패

				//실패일 경우 Count ++
				await _userManager.AccessFailedAsync(user);

				//잠금 설정 유저인지
				if (await _userManager.IsLockedOutAsync(user))
				{
					//잠긴 상태인 유저의 리턴 메세지
					var content = $"Your account is locked out. " +
						$"If you want to reset the password, you can use the " +
						$"Forgot Password link on the Login page";

					//이메일 문구 생성
					var message = new Message(new string[] { userForAuthenticationDto.Email },
						"Locked out account information", content, null);

					//이메일 전송
					await _emailSender.SendEmailAsync(message);

					//401 Error
					return Unauthorized(new AuthResponseDto
					{
						ErrorMessage = "The account is locked out"
					});
				}

				//401 Error
				return Unauthorized(new AuthResponseDto
				{
					ErrorMessage = "Invalid Authentication"
				});
			}

			//2단계 인증이 활성화 된경우
			if (await _userManager.GetTwoFactorEnabledAsync(user))
			{
				//유저의 공급 방식이 Email일 경우
				var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);

				if (providers.Contains(userForAuthenticationDto.TwoFactorType))
				{
					if (userForAuthenticationDto.TwoFactorType == "Authenticator")
					{
						return Ok(new AuthResponseDto
						{
							Is2StepVerificationRequired = true,
							Provider = "Authenticator"
						});
					}
					else if (userForAuthenticationDto.TwoFactorType == "Email")
					{
						//2단계 인증 확인에 따른 메일 발송(현재여기서는)
						await TwoStepVerificationSendEmail(user);

						return Ok(new AuthResponseDto
						{
							Is2StepVerificationRequired = true,
							Provider = "Email"
						});

					}
				}


				//2단계 인증 확인에 따른 메일 발송(현재여기서는)
				await TwoStepVerificationSendEmail(user);

				return Ok(new AuthResponseDto
				{
					Is2StepVerificationRequired = true,
					Provider = "Email"
				});
			}

			//2단계 인증이 비활성화 인경우
			var tokenResult = await GetGenerateUserAuthToken(user);

			//정보값 리턴
			return Ok(tokenResult);
		}

		/// <summary>
		/// 로그인 인증 메일 발송
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		private async Task TwoStepVerificationSendEmail(User user)
		{

			//토큰 생성
			var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

			var emailContent = $@"
			<p>로그인 인증 확인</p>			
			<p> 
				입력 토큰 : {token}
			</p>";

			//메일 구조 생성
			var message = new Message(new string[] { user.Email }, "로그인 인증 확인",
				emailContent, null);

			//메일 발송
			await _emailSender.SendEmailAsync(message);
		}


		/// <summary>
		/// 로그인 메일 인증
		/// </summary>
		/// <remarks>
		/// 메일로 전송된 인증번호를 통해 로그인 완료
		/// </remarks>
		/// <param name="twoFactorVerificationDto"></param>
		/// <returns></returns>
		[HttpPost("Login/Email/Verification")]
		public async Task<IActionResult> TwoStepEmailVerification(
			[FromBody] EmailTwoFactorDto twoFactorVerificationDto)
		{
			if (!ModelState.IsValid)
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});

			//email로 유저 찾기
			var user = await _userManager.FindByEmailAsync(twoFactorVerificationDto.Email);
			if (user == null) {
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});
			}


			//유저의 인증 방식과 토큰 이 일치하는지 확인
			var validVerification = await _userManager.VerifyTwoFactorTokenAsync(user,
				TokenOptions.DefaultEmailProvider, twoFactorVerificationDto.TwoFactorToken);

			if (!validVerification)
			{
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Token Verification"
				});
			}
			var resultTokenData = await GetGenerateUserAuthToken(user);
			return Ok(resultTokenData);
		}

		/// <summary>
		/// OTP 로그인 인증 
		/// </summary>
		/// <param name="verifyAuthenticator"></param>
		/// <returns></returns>
		[HttpPost("Login/OTP/Verification")]
		public async Task<IActionResult> TwoStepOTPVerification([FromBody] GoogleTwoFactorConfirmDto verifyAuthenticator)
		{
			if (verifyAuthenticator == null || verifyAuthenticator.VerificationCode == null || verifyAuthenticator.Email == null)
			{
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});
			}

			//email로 유저 찾기
			var user = await _userManager.FindByEmailAsync(verifyAuthenticator.Email);
			if (user == null)
			{
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});
			}

			//2단계 인증을 사용하는지

			//2단계 인증에서 OTP를 사용하는지

			//복구 코드는 존재하는지

			var verificationCode = verifyAuthenticator.VerificationCode.Replace(" ", string.Empty).Replace("-", string.Empty);

			var is2FaTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
				user, TokenOptions.DefaultAuthenticatorProvider, verificationCode);

			if (!is2FaTokenValid)
			{
				return BadRequest("error");
			}

			var resultTokenData = await GetGenerateUserAuthToken(user);

			return Ok(resultTokenData);

		}

		/// <summary>
		/// 로그인 성공시 토큰 발행
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		private async Task<AuthResponseDto> GetGenerateUserAuthToken(User user)
		{
			//유저 토큰 생성
			var token = await _service.AccountService.GetToken(user);

			//리프레시 토큰 생성
			user.RefreshToken = _service.AccountService.GenerateRefreshToken();

			//리프레시 토큰 만료기간
			user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

			//유저 정보 업데이트
			await _userManager.UpdateAsync(user);

			//인증 실패 갯수 초기화
			await _userManager.ResetAccessFailedCountAsync(user);

			//2단계 인증을 사용을 하고 있는지
			var _is2StepVerificationRequired = await _userManager.GetTwoFactorEnabledAsync(user);

			//결과값 리턴
			return new AuthResponseDto
			{
				IsAuthSuccessful = true,
				Token = token,
				RefreshToken = user.RefreshToken,
				Is2StepVerificationRequired = _is2StepVerificationRequired
			};
		}

		/// <summary>
		/// 패스워드 초기화 요청(메일 전송)
		/// </summary>
		/// <remarks>
		/// 패스워드 초기화를 위한 메일 전송
		/// </remarks>
		/// <param name="forgotPasswordDto"></param>
		/// <returns></returns>
		[HttpPost("ResetPassword")]
		public async Task<IActionResult> ForgotPassword( [FromBody] ForgotPasswordDto forgotPasswordDto)
		{
			//Body 비정상
			if (forgotPasswordDto == null || forgotPasswordDto.Email == null
				|| forgotPasswordDto.ClientURI == null)
			{
				return BadRequest("Invalid Request");
			}

			
			var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
			
			//해당 유저 없음
			if (user == null) {
				return BadRequest("Invalid Request");
			}

			//비번 리셋을 위한 토큰 생성
			var token = await _userManager.GeneratePasswordResetTokenAsync(user);

			//url을 만들기 위한 dic
			var param = new Dictionary<string, string?>
			{
				{ "token", token },
				{ "email", forgotPasswordDto.Email }
			};

			//url 생성 = 고정 url을 가지고 있다면 client를 통해 받을 필요없음
			var callback = QueryHelpers.AddQueryString(forgotPasswordDto.ClientURI, param);

			var emailContent = $@"
				<p>패스워드 초기화 확인</p>			
				<p> 
					<a href='{callback}'>
					   <input type='image' src='https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_92x30dp.png' border='0' alt='Submit' style='width: 50px;' />
					</a>
				</p>";

			//이메일 메세지 생성
			var message = new Message(new string[] { user.Email }, "패스워드 초기화 확인",
				emailContent, null);

			//메일 전송
			await _emailSender.SendEmailAsync(message);

			return Ok();
		}

		/// <summary>
		/// 패스워드 초기화 패스워드 재설정 
		/// </summary>
		/// <remarks>
		/// 이메일로 전송된 토큰사용
		/// 메일로 전송된 토큰에서 url로 인코딩이 되어있다면 디코딩을 통해 정상문자열로 변경하여야 동작이가능하다
		/// </remarks>
		/// <param name="resetPasswordDto"></param>
		/// <returns></returns>
		[HttpPost("ResetPassword/Confirmation")]
		public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
		{

			var errorResponse = new ResetPasswordResponseDto
			{
				Errors = new string[] { "Reset Password Failed" }
			};

			//Body 비정상
			if (!ModelState.IsValid) {
				return BadRequest(errorResponse);
			}

			var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);
			
			//해당 유저 없음
			if (user == null) {
				return BadRequest(errorResponse);
			}

			//유저 정보 객체 + 패스워드 리셋 토큰 + 변경할 비번 을 통해 변경시도
			var resetPassResult = await _userManager.ResetPasswordAsync(user,
				resetPasswordDto.Token, resetPasswordDto.Password);


			//조건에 맞지 않다면 fail
			if (!resetPassResult.Succeeded)
			{
				var errors = resetPassResult.Errors.Select(e => e.Description);
				return BadRequest(new ResetPasswordResponseDto { Errors = errors });
			}

			//만약 잠금일자가 있었다면 잠금해제
			await _userManager.SetLockoutEndDateAsync(user, null);

			//결과값 전송
			return Ok(new ResetPasswordResponseDto { IsResetPasswordSuccessful = true });
		}
	}
}
