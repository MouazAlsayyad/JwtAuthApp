using System.ComponentModel.DataAnnotations;

namespace JwtAuthApp.Core.Models
{
    public sealed class LoginModel
    {
        [Required, EmailAddress]
        public required string Email { get; init; }
        [Required, MinLength(6)]
        public required string Password { get; init; }
    }
}
