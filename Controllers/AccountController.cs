using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

[ApiController]
[Route("api/account")]
public class AccountController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _configuration;

    public AccountController(UserManager<ApplicationUser> userManager,
                            RoleManager<ApplicationRole> roleManager, 
                            SignInManager<ApplicationUser> signInManager, 
                            IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        var user = new ApplicationUser { UserName = model.Username, Email = model.Email, FirstName = model.FirstName, LastName = model.LastName };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            return Ok();
        }

        return BadRequest(result.Errors);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        return Unauthorized();
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok();
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        var user = await _userManager.GetUserAsync(User);

        if (user == null)
        {
            return NotFound();
        }

        return Ok(user);
    }

    [HttpGet("users")]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _userManager.Users.ToListAsync();
        return Ok(users);
    }

    [HttpDelete("delete/{id}")]
    [Authorize(Policy = "SuperAdmin")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
        {
            return NotFound();
        }

        await _signInManager.SignOutAsync();

        var result = await _userManager.DeleteAsync(user);
        if (result.Succeeded)
        {
            return Ok();
        }

        return BadRequest(result.Errors);
    }

    [HttpDelete("delete")]
    [Authorize]
    public async Task<IActionResult> DeleteCurrentUser()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        await _signInManager.SignOutAsync();

        var result = await _userManager.DeleteAsync(user);
        if (result.Succeeded)
        {
            return Ok();
        }

        return BadRequest(result.Errors);
    }

    [HttpPost("add-role")]
    [Authorize(policy: "SuperAdmin")]
    public async Task<IActionResult> AddRole([FromBody] AddRoleModel model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null)
        {
            return NotFound();
        }

        var role = await _roleManager.FindByNameAsync(model.RoleName);
        if (role == null)
        {
            return NotFound();
        }

        var result = await _userManager.AddToRoleAsync(user, role.Name);
        if (result.Succeeded)
        {
            return Ok();
        }

        return BadRequest(result.Errors);
    }

    [HttpPost("remove-role")]
    [Authorize(policy: "SuperAdmin")]
    public async Task<IActionResult> RemoveRole([FromBody] AddRoleModel model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null)
        {
            return NotFound();
        }

        var role = await _roleManager.FindByNameAsync(model.RoleName);
        if (role == null)
        {
            return NotFound();
        }

        var result = await _userManager.RemoveFromRoleAsync(user, role.Name);
        if (result.Succeeded)
        {
            return Ok();
        }

        return BadRequest(result.Errors);
    }

    private async Task<string> GenerateJwtToken(ApplicationUser user)
    {
        var userRoles = await _userManager.GetRolesAsync(user);

        var roleClaims = new List<Claim>();
        foreach (var role in userRoles)
        {
            var rolePermissions = await _roleManager.FindByNameAsync(role);
            if (rolePermissions != null)
            {
                roleClaims.AddRange(rolePermissions.RolePermissions.Select(p => new Claim("Permission", p.ToString())));
            }
        }

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.UserName),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(ClaimTypes.NameIdentifier, user.Id)
        };

        claims.AddRange(roleClaims);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(Convert.ToDouble(_configuration["Jwt:DurationInMinutes"])),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public class RegisterModel
{
    public required string Username { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
}

public class LoginModel
{
    public required string Username { get; set; }
    public required string Password { get; set; }
}

public class AddRoleModel
{
    public required string UserId { get; set; }
    public required string RoleName { get; set; }
}
