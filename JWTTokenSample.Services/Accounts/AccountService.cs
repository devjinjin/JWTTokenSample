using JWTTokenSample.Entities.ConfigurationModels;
using JWTTokenSample.Repository;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

namespace JWTTokenSample.Services.Authentications
{


    internal sealed class AccountService : IAccountService
	{
		private readonly IRepositoryManager _repository;
		private readonly JwtConfiguration _jwtSettings;
		private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;


		public AccountService(
			IRepositoryManager repository,
			IOptions<JwtConfiguration> jwtSettings)
		{
			_repository = repository;
			_jwtSettings = jwtSettings.Value;
			_jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
		}
    }
}
