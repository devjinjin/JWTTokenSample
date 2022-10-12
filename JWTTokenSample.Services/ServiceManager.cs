using JWTTokenSample.Entities.ConfigurationModels;
using JWTTokenSample.Repository;
using JWTTokenSample.Services.Authentications;
using Microsoft.Extensions.Options;

namespace JWTTokenSample.Services
{
    public class ServiceManager : IServiceManager
    {
        private readonly Lazy<IAccountService> _accountService;


        public ServiceManager(IRepositoryManager repositoryManager, IOptions<JwtConfiguration> jwtSettings)
        {
            _accountService = new Lazy<IAccountService>(() => new AccountService(repositoryManager, jwtSettings));
        }

        public IAccountService AccountService => _accountService.Value;
    }
}
