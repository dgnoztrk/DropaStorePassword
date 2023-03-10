using DropaStorePassword.Data;
using DropaStorePassword.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DropaStorePassword.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly DB _db;
        public AuthController(DB db)
        {
            _db = db;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> GetToken(LoginViewModel model)
        {
            var _user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Email == model.Email);
            if (_user != null)
            {
                var hasher = new PasswordHasher<AppUser>();
                var hashpw = hasher.VerifyHashedPassword(_user, _user.PasswordHash!, model.Password);
                if (hashpw == PasswordVerificationResult.Success)
                {
                    return Ok(CreateToken(_user));
                }
            }
            //HttpContext.Response.StatusCode = 500;
            //throw new Exception("E-posta veya şifre hatalı !");
            return BadRequest("E-posta veya şifre hatalı !");
        }


        [HttpGet("CreateUser")]
#pragma warning disable IDE0051 // Remove unused private members
        private async Task<object> CreateUser()
#pragma warning restore IDE0051 // Remove unused private members
        {
            var user = new AppUser();
            user.Email = "info@doganozturk.net";
            user.Id = Guid.NewGuid().ToString();
            var hasher = new PasswordHasher<AppUser>();
            var hashpw = hasher.HashPassword(user, "test");
            user.PasswordHash = hashpw;
            await _db.Users.AddAsync(user);
            await _db.SaveChangesAsync();
            return Ok(user);
        }

        private string CreateToken(AppUser user)
        {
            string result = "";
            List<Claim> claims = new List<Claim>{
                new Claim(ClaimTypes.Name,user.Email!),
                new Claim("ID",user.Id)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(GlobalVariables.Token));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var jwt = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(3), signingCredentials: cred);
            result = new JwtSecurityTokenHandler().WriteToken(jwt);
            return result;
        }
    }
}
