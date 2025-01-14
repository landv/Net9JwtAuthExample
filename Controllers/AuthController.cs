using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using JwtAuthExample.Models;
using Microsoft.Extensions.Configuration;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly string _jwtKey;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;

    public AuthController(IConfiguration configuration)
    {
        _configuration = configuration;
        _jwtKey = _configuration.GetSection("JwtSettings:Key").Value 
            ?? throw new InvalidOperationException("JWT Key not found in configuration");
        _jwtIssuer = _configuration.GetSection("JwtSettings:Issuer").Value 
            ?? throw new InvalidOperationException("JWT Issuer not found in configuration");
        _jwtAudience = _configuration.GetSection("JwtSettings:Audience").Value 
            ?? throw new InvalidOperationException("JWT Audience not found in configuration");
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // TODO: Replace with actual user authentication logic
        var (isValid, userRole) = ValidateUser(request.Username, request.Password);
        
        if (isValid)
        {
            var token = GenerateJwtToken(request.Username, userRole);
            return Ok(new { Token = token });
        }

        return Unauthorized();
    }

    private (bool isValid, string role) ValidateUser(string? username, string? password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return (false, string.Empty);
            
        if (username == "admin" && password == "password")
            return (true, "Admin");
        
        if (username == "user" && password == "password")
            return (true, "User");
        
        return (false, string.Empty);
    }

    private string GenerateJwtToken(string? username, string? role)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(role))
            throw new ArgumentException("Username and role cannot be null or empty");

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_jwtKey);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, role)
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Issuer = _jwtIssuer,
            Audience = _jwtAudience
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    [HttpGet("admin")]
    [Authorize(Policy = "AdminPolicy")]
    public IActionResult AdminEndpoint()
    {
        try
        {
            return Ok("Hello Admin!");
        }
        catch (Exception)
        {
            return StatusCode(500, new { message = "An error occurred accessing the admin endpoint" });
        }
    }

    [HttpGet("user")]
    [Authorize(Policy = "UserPolicy")]
    public IActionResult UserEndpoint()
    {
        try
        {
            return Ok("Hello User!");
        }
        catch (Exception)
        {
            return StatusCode(500, new { message = "An error occurred accessing the user endpoint" });
        }
    }

    [HttpGet("all")]
    [Authorize]
    public IActionResult AllUsersEndpoint()
    {
        return Ok("Hello Authenticated User!");
    }

}
