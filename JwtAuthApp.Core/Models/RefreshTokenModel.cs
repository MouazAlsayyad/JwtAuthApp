using System.ComponentModel.DataAnnotations;

namespace JwtAuthApp.Core.Models
{
    public class RefreshTokenModel
    {
        [Required]
        public required string AccessToken { get; set; }

        [Required]
        public required string RefreshToken { get; set; }
    }
}
