using JWTTokenSample.Repository.Accounts;
using Microsoft.Extensions.Configuration;

namespace JWTTokenSample.Repository
{
    public sealed class RepositoryManager : IRepositoryManager
    {
        private readonly ApplicationDbContext _repositoryContext;


        private readonly Lazy<IAccountRepository> _account;
      
        public RepositoryManager(ApplicationDbContext repositoryContext, IConfiguration config)
        {
            _repositoryContext = repositoryContext;         
            _account = new Lazy<IAccountRepository>(() => new AccountRepository(_repositoryContext));
        }

        public IAccountRepository Account => _account.Value;

        public async Task SaveAsync()
        {
            await _repositoryContext.SaveChangesAsync();
        }
    }
}
