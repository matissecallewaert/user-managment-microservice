using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/roles")]
[Authorize(Policy = "SuperAdmin")]
public class RoleController : ControllerBase
{
    private readonly RoleManager<ApplicationRole> _roleManager;

    public RoleController(RoleManager<ApplicationRole> roleManager)
    {
        _roleManager = roleManager;
    }

    [HttpPost("create")]
    public async Task<IActionResult> CreateRole([FromBody] CreateRoleModel roleModel)
    {
        var role = new ApplicationRole { Name = roleModel.RoleName, Description = roleModel.Description, RolePermissions = roleModel.RolePermissions };
        var result = await _roleManager.CreateAsync(role);

        if (result.Succeeded)
        {
            return Ok();
        }

        return BadRequest(result.Errors);
    }
}

public class CreateRoleModel
{
    public required string RoleName { get; set; }
    public string? Description { get; set; }
    public required List<Permissions> RolePermissions { get; set; }
}
