using JWTTokenSample.Entities.ConfigurationModels;
using JWTTokenSample.Repository;
using JWTTokenSample.Services.Authentications;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace JWTTokenSample.Services
{
    public class ServiceManager : IServiceManager
    {
        private readonly Lazy<IAccountService> _accountService;


        public ServiceManager(IRepositoryManager repositoryManager, IOptions<JwtConfiguration> jwtSettings, UserManager<Entities.Models.User> _userManager)
        {
            _accountService = new Lazy<IAccountService>(() => new AccountService(jwtSettings, _userManager));
        }

        public IAccountService AccountService => _accountService.Value;
    }
}
