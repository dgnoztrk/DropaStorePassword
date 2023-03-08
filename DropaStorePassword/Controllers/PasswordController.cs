using DropaStorePassword.Data;
using DropaStorePassword.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DropaStorePassword.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class PasswordController : ControllerBase
    {
        private readonly DB _db;

        public PasswordController(DB db)
        {
            _db = db;
        }

        [HttpGet("GetPasswords")]
        public async Task<IActionResult> GetPasswordsAsync()
        {
            var userId = User.GetIdClaim();
            if (string.IsNullOrEmpty(userId))
            {
                return NotFound();
            }
            var pws = await _db.Passwords.Where(a => a.AppUserId == userId).AsNoTracking().ToListAsync();
            return Ok(pws);
        }

        [HttpGet("GetPasswordById/{Id}")]
        public async Task<IActionResult> GetPasswordById(long Id)
        {
            var userId = User.GetIdClaim();
            if (string.IsNullOrEmpty(userId))
            {
                return NotFound();
            }
            var pws = await _db.Passwords.AsNoTracking().FirstOrDefaultAsync(x => x.ID == Id && x.AppUserId == userId);
            return Ok(pws);
        }

        [HttpPost("SavePassword")]
        public async Task<IActionResult> SavePassword(SavePasswordViewModel mod)
        {
            var userId = User.GetIdClaim();
            if (string.IsNullOrEmpty(userId))
            {
                return NotFound();
            }
            var model = new Password();
            var appUser = await _db.Users.AsNoTracking().FirstOrDefaultAsync(x => x.Id == userId);
            if (appUser == null)
            {
                return NotFound();
            }
            model.AppUserId = appUser.Id;
            model.UserName = mod.UserName;
            model.PasswordHash = mod.Password.Encrypt(appUser.Id);
            await _db.Passwords.AddAsync(model);
            await _db.SaveChangesAsync();
            mod.Password = model.PasswordHash;
            return Ok(mod);
        }

        [HttpPut("UpdatePassword")]
        public async Task<IActionResult> UpdatePassword(UpdatePasswordViewModel mod)
        {
            var userId = User.GetIdClaim();
            bool change = false;
            var dbPass = await _db.Passwords.FirstOrDefaultAsync(x => x.ID == mod.ID && x.AppUserId == userId);
            if (dbPass == null)
            {
                return NotFound();
            }
            if (dbPass.UserName != mod.UserName)
            {
                dbPass.UserName = mod.UserName;
                change = true;
            }
            if (!string.IsNullOrEmpty(mod.Password))
            {
                var _password = mod.Password.Encrypt(userId!);
                if (dbPass.PasswordHash != _password)
                {
                    dbPass.PasswordHash = _password;
                    change = true;
                }
            }
            if (change)
            {
                await _db.SaveChangesAsync();
            }
            return Ok(new { dbPass.UserName, dbPass.PasswordHash });
        }

        [HttpPost("ViewPassword")]
        public async Task<IActionResult> ViewPassword([FromBody] string PasswordHash)
        {
            var userId = User.GetIdClaim();
            if (string.IsNullOrEmpty(userId))
            {
                return NotFound();
            }
            var any = await _db.Passwords.AnyAsync(a => a.PasswordHash == PasswordHash && a.AppUserId == userId);
            if (any)
            {
                return Ok(PasswordHash.Decrypt(userId!));
            }
            return BadRequest();
        }

        [HttpDelete("RemovePassword/{Id}")]
        public async Task<IActionResult> RemovePassword(long Id)
        {
            var userId = User.GetIdClaim();
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest();
            }
            var pws = await _db.Passwords.AsNoTracking().FirstOrDefaultAsync(x => x.ID == Id && x.AppUserId == userId);
            if (pws != null)
            {
                _db.Passwords.Remove(pws);
                bool result = await _db.SaveChangesAsync() > 0;
                return result ? Ok() : BadRequest();
            }
            return BadRequest();
        }
    }
}