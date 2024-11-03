using Microsoft.AspNetCore.Identity;
using UserManagment.Enums;

namespace UserManagment.Entities;

public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    
    public List<Permissions> RolePermissions { get; set; } = [];
}
