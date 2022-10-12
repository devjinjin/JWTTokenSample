using JWTTokenSample.Services.Authentications;

namespace JWTTokenSample.Services
{
    public interface IServiceManager
    {
        IAccountService AccountService { get; }

    }
}
