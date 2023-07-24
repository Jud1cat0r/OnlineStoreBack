using AuthAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthAPI.Context
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) 
        { 
        }

        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
            modelBuilder.Entity<User>().Property(c => c.UserName).IsRequired();
            modelBuilder.Entity<User>().Property(c => c.Password).IsRequired();
            modelBuilder.Entity<User>().Property(c => c.FirstName).IsRequired();
            modelBuilder.Entity<User>().Property(c => c.Email).IsRequired();
            modelBuilder.Entity<User>().Property(c => c.Role).IsRequired(false);
            modelBuilder.Entity<User>().Property(c => c.Token).IsRequired(false);
        }
    }
}
