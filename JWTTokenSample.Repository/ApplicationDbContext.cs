using JWTTokenSample.Entities.Models.Accounts;
using Microsoft.EntityFrameworkCore;

namespace JWTTokenSample.Repository
{
    public class ApplicationDbContext : DbContext
    {
        //Microsoft.EntityFrameworkCore.SqlServer 추가
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
       : base(options)
        {

        }

        
        public DbSet<AccountModel>? Accounts { get; set; }
    }
}
