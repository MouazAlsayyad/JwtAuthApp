using JwtAuthApp.Core.Entities;
using System.Security.Claims;

namespace JwtAuthApp.Core.Interfaces
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user);
        string GenerateRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
