using JWTTokenSample.Repository.Accounts;

namespace JWTTokenSample.Repository
{
    public interface IRepositoryManager
    {
        IAccountRepository Account { get; }

        //저장 처리
        Task SaveAsync();
    }
}
