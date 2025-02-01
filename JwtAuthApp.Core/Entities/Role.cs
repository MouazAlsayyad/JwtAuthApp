using Microsoft.AspNetCore.Identity;

namespace JwtAuthApp.Core.Entities
{
    public class Role : IdentityRole
    {
        public ICollection<RolePermission> RolePermissions { get; set; }
    }
}
