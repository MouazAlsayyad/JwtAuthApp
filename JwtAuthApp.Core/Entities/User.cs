using Microsoft.AspNetCore.Identity;

namespace JwtAuthApp.Core.Entities
{
    public class User : IdentityUser
    {
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public ICollection<UserRole> UserRoles { get; set; }
    }
}
