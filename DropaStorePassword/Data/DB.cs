using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace DropaStorePassword.Data
{
    public class DB : IdentityDbContext<AppUser, IdentityRole, string>
    {
        public DB(DbContextOptions<DB> options) : base(options)
        {
        }
        public DbSet<Password> Passwords { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite(@"DataSource=DropaStorePassword.db;");
        }
    }
}