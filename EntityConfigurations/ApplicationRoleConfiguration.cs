using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using UserManagment.Entities;
using UserManagment.Enums;

namespace UserManagment.EntityConfigurations;

public class ApplicationRoleConfiguration : IEntityTypeConfiguration<ApplicationRole>
{
    public void Configure(EntityTypeBuilder<ApplicationRole> builder)
    {
        builder.Property(r => r.RolePermissions)
            .HasConversion(
                v => string.Join(',', v.Select(p => p.ToString())),
                v => v.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(p => Enum.Parse<Permissions>(p)).ToList()
            );

        builder.Property(r => r.Description).HasMaxLength(256);
    }
}
