using JwtAuthApp.Core.Entities;
using JwtAuthApp.Core.Models;
using JwtAuthApp.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JwtAuthApp.Infra
{
    public static class SeedData
    {
        public static async Task Initialize(IServiceProvider serviceProvider)
        {
            using var scope = serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<Role>>();

            // Ensure the database is created and migrated
            await context.Database.MigrateAsync();

            // Seed Roles
            await SeedRoles(roleManager);

            // Seed Permissions
            await SeedPermissions(context);

            // Seed Admin User
            await SeedAdminUser(userManager);
        }

        private static async Task SeedRoles(RoleManager<Role> roleManager)
        {
            string[] roleNames = { Roles.ADMIN, Roles.USER };

            foreach (var roleName in roleNames)
            {
                var roleExists = await roleManager.RoleExistsAsync(roleName);
                if (!roleExists)
                {
                    await roleManager.CreateAsync(new Role { Name = roleName });
                }
            }
        }

        private static async Task SeedPermissions(ApplicationDbContext context)
        {
            if (!context.Permissions.Any())
            {
                var permissions = new[]
                {
                    new Permission { Name = "CreateUser" },
                    new Permission { Name = "DeleteUser" },
                    new Permission { Name = "EditUser" },
                    new Permission { Name = "ViewUser" }
                };

                await context.Permissions.AddRangeAsync(permissions);
                await context.SaveChangesAsync();
            }
        }

        private static async Task SeedAdminUser(UserManager<User> userManager)
        {
            var adminUser = await userManager.FindByNameAsync("admin");
            if (adminUser == null)
            {
                adminUser = new User
                {
                    UserName = "admin",
                    Email = "admin@example.com",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(adminUser, "Admin@123");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                }
            }
        }
    }
}