using JwtAuthApp.Core.Entities;
using JwtAuthApp.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace JwtAuthApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController(UserManager<User> userManager) : ControllerBase
    {
        private readonly UserManager<User> _userManager = userManager;


        [Authorize(Roles = Roles.ADMIN)]
        [HttpGet]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            return Ok(users);
        }

        [Authorize(Roles = Roles.ADMIN)]
        [HttpGet("{id}")]
        public async Task<IActionResult> GetUserById(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound("User not found.");
            return Ok(user);
        }

        [Authorize(Roles = Roles.ADMIN)]
        [HttpGet("email/{email}")]
        public async Task<IActionResult> GetUserByEmail(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return NotFound("User not found.");
            return Ok(user);
        }

        [Authorize(Roles = Roles.ADMIN)]
        [HttpPost("toggle-status/{id}")]
        public async Task<IActionResult> ToggleUserStatus(string id)
        {
            // Find the user by ID
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound("User not found.");
            }

            if (user.LockoutEnd != null && user.LockoutEnd > DateTime.UtcNow)
            {
                // User is deactivated, so we activate them
                user.LockoutEnd = null; // Remove the lockout end time to reactivate
                user.LockoutEnabled = false; // Disable lockout
                await _userManager.UpdateAsync(user);

                return Ok(new { message = "User activated" });
            }
            else
            {
                // User is currently active, so we deactivate them
                user.LockoutEnd = DateTime.UtcNow.AddYears(100); // Set a far future date to lock the user out
                user.LockoutEnabled = true; // Enable lockout
                await _userManager.UpdateAsync(user);

                return Ok(new { message = "User deactivated" });
            }
        }

        [Authorize]
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null) return Unauthorized("User not authenticated.");

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound("User not found.");

            return Ok(new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.PhoneNumber
            });
        }
    }
}
