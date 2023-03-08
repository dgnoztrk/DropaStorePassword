using Microsoft.AspNetCore.Identity;

namespace DropaStorePassword.Data
{
    public class AppUser : IdentityUser<string>
    {
        public ICollection<Password>? Passwords { get; set; }
    }
}