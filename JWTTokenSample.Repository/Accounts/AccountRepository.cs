using JWTTokenSample.Entities.Models.Accounts;

namespace JWTTokenSample.Repository.Accounts
{
    public class AccountRepository : RepositoryBase<AccountModel>, IAccountRepository
    {
        public AccountRepository(ApplicationDbContext repositoryContext) : base(repositoryContext)
        {
        }
    }
}
