using EmailService;
using JWTTokenSample.Entities.Models;
using JWTTokenSample.Services;
using JWTTokenSample.Shared.DTO;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace JWTTokenSample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
		private readonly UserManager<User> _userManager;
		private readonly IServiceManager _service;
		private readonly IEmailSender _emailSender;

		public AccountController(UserManager<User> userManager,
			IServiceManager service,
			IEmailSender emailSender)
		{
			_userManager = userManager;
			_service = service;
			_emailSender = emailSender;
		}

		/// <summary>
		/// 회원가입 = 2단계 인증 포함(이메일)
		/// </summary>
		/// <param name="userForRegistrationDto"></param>
		/// <returns></returns>

		[HttpPost("register")]
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

			//2단계인증 활성화 등록 (안할거면 false)
			await _userManager.SetTwoFactorEnabledAsync(user, true);

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
		/// 로그인 요청
		/// </summary>
		/// <param name="userForAuthenticationDto"></param>
		/// <returns></returns>
		[HttpPost("login")]
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
			if (await _userManager.GetTwoFactorEnabledAsync(user)) {

				//2단계 인증 확인에 따른 메일 발송(현재여기서는)
				return await GenerateOTPFor2StepVerification(user);
			}

			//2단계 인증이 비활성화 인경우

			//토큰 생성
			var token = await _service.AccountService.GetToken(user);

			//리프레시 토큰 생성
			user.RefreshToken = _service.AccountService.GenerateRefreshToken();

			//리프레시 토큰 만료기간 설정
			user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);

			//유저 정보 업데이트
			await _userManager.UpdateAsync(user);

			//로그인 실패 갯수 초기화
			await _userManager.ResetAccessFailedCountAsync(user);

			//정보값 리턴
			return Ok(new AuthResponseDto
			{
				IsAuthSuccessful = true,
				Token = token,
				RefreshToken = user.RefreshToken
			});
		}

		/// <summary>
		/// 이메일 인증 확인용
		/// </summary>
		/// <param name="email"></param>
		/// <param name="token"></param>
		/// <returns></returns>
		[HttpGet("EmailConfirmation")]
		public async Task<IActionResult> EmailConfirmation([FromQuery] string email, [FromQuery] string token)
		{
			var user = await _userManager.FindByEmailAsync(email);
			if (user == null) {
				return BadRequest();
			}

			var confirmResult = await _userManager.ConfirmEmailAsync(user, token);
			if (!confirmResult.Succeeded) {
				return BadRequest();
			}

			return Ok();
		}

		/// <summary>
		/// 로그인 후 2단계인증 확인 용
		/// </summary>
		/// <param name="twoFactorVerificationDto"></param>
		/// <returns></returns>
		[HttpPost("TwoStepVerification")]
		public async Task<IActionResult> TwoStepVerification(
			[FromBody] TwoFactorVerificationDto twoFactorVerificationDto)
		{
			if (!ModelState.IsValid)
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});

			//email로 유저 찾기
			var user = await _userManager.FindByEmailAsync(twoFactorVerificationDto.Email);
			if (user == null)
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Request"
				});

			//유저의 인증 방식과 토큰 이 일치하는지 확인
			var validVerification = await _userManager.VerifyTwoFactorTokenAsync(user,
				twoFactorVerificationDto.Provider, twoFactorVerificationDto.TwoFactorToken);

			if (!validVerification)
				return BadRequest(new AuthResponseDto
				{
					ErrorMessage = "Invalid Token Verification"
				});

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

			//결과값 리턴
			return Ok(new AuthResponseDto
			{
				IsAuthSuccessful = true,
				Token = token,
				RefreshToken = user.RefreshToken
			});
		}

		/// <summary>
		/// 로그인시 (2단계 인증 메일 발송)
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		private async Task<IActionResult> GenerateOTPFor2StepVerification(User user)
		{
			//유저의 공급 방식이 Email일 경우
			var providers = await _userManager.GetValidTwoFactorProvidersAsync(user);
			if (!providers.Contains("Email"))
			{
				return Unauthorized(new AuthResponseDto
				{
					ErrorMessage = "Invalid 2-Step Verification Provider"
				});
			}
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

			return Ok(new AuthResponseDto
			{
				Is2StepVerificationRequired = true,
				Provider = "Email"
			});
		}
	}
}
