using JWTTokenSample.Entities.Models;
using JWTTokenSample.Repository.Configuration;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTTokenSample.Repository
{
    public class ApplicationDbContext : IdentityDbContext<User>
    {
        //Microsoft.EntityFrameworkCore.SqlServer 추가
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
       : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.ApplyConfiguration(new RoleConfiguration());
        }

        //public DbSet<AccountModel>? Accounts { get; set; }
    }
}
