using JWTTokenSample.Entities.ConfigurationModels;
using JWTTokenSample.Entities.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTTokenSample.Services.Authentications
{


    internal sealed class AccountService : IAccountService
	{
		//private readonly IRepositoryManager _repository;
		private readonly JwtConfiguration _jwtSettings;
		private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;
		private readonly UserManager<User> _userManager;

		public AccountService(
			//IRepositoryManager repository,
			IOptions<JwtConfiguration> jwtSettings,
			UserManager<User> userManager)
		{
			//_repository = repository;
			_jwtSettings = jwtSettings.Value;
			_jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
			_userManager = userManager;
		}

		/// <summary>
		/// jwt 토큰 생성
		/// </summary>
		/// <param name="user"></param>
		/// <returns></returns>
		public async Task<string> GetToken(User user)
		{
			var signingCredentials = GetSigningCredentials();

			var claims = await GetClaims(user);

			//정보 조합하여 토큰 생성
			var tokenOptions = GenerateTokenOptions(signingCredentials, claims);

			return _jwtSecurityTokenHandler.WriteToken(tokenOptions);
		}


		private SigningCredentials GetSigningCredentials()
		{
			var key = Encoding.UTF8.GetBytes(_jwtSettings.ValidSecretKey ?? "");
			var secret = new SymmetricSecurityKey(key);

			return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
		}

		private async Task<IEnumerable<Claim>> GetClaims(User user)
		{
			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.Name, user.Email)
			};

			var roles = await _userManager.GetRolesAsync(user);
			foreach (var role in roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			return claims;
		}

		/// <summary>
		/// 정보 조합 토큰 생성
		/// </summary>
		/// <param name="signingCredentials"></param>
		/// <param name="claims"></param>
		/// <returns></returns>
		private JwtSecurityToken GenerateTokenOptions
			(SigningCredentials signingCredentials, IEnumerable<Claim> claims)
		{
			var tokenOptions = new JwtSecurityToken(
				issuer: _jwtSettings.ValidIssuer,
				audience: _jwtSettings.ValidAudience,
				claims: claims,
				expires: DateTime.Now.AddMinutes(Convert.ToDouble
					(_jwtSettings.Expires)),
				signingCredentials: signingCredentials);

			//expires 최소 시간은 5분임

			return tokenOptions;
		}

		/// <summary>
		/// 리프레시 토큰 생성
		/// </summary>
		/// <returns></returns>
		public string GenerateRefreshToken()
		{
			var randomNumber = new byte[32];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(randomNumber);
				return Convert.ToBase64String(randomNumber);
			}
		}

		/// <summary>
		/// 기존 토큰으로 정보 획득
		/// </summary>
		/// <param name="token"></param>
		/// <returns></returns>
		/// <exception cref="SecurityTokenException"></exception>
		public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
		{
			//토큰 파라미터 정보
			var tokenValidationParameters = new TokenValidationParameters
			{
				ValidateAudience = true,
				ValidateIssuer = true,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(
					Encoding.UTF8.GetBytes(_jwtSettings.ValidSecretKey ?? "")),
				ValidateLifetime = false,
				ValidIssuer = _jwtSettings.ValidIssuer,
				ValidAudience = _jwtSettings.ValidAudience,
			};

			var tokenHandler = new JwtSecurityTokenHandler();
			
			SecurityToken securityToken;

			var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);

			var jwtSecurityToken = securityToken as JwtSecurityToken;
			if (jwtSecurityToken == null ||
				!jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
				StringComparison.InvariantCultureIgnoreCase))
			{
				throw new SecurityTokenException("Invalid token");
			}

			return principal;
		}
	}
}
