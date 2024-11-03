using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UserManagment.Entities;
using UserManagment.EntityConfigurations;

public class UserManagmentDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, string>
{
    public UserManagmentDbContext(DbContextOptions<UserManagmentDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        builder.ApplyConfiguration(new ApplicationRoleConfiguration());
    }
}
