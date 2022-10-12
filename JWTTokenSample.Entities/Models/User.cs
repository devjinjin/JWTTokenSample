using Microsoft.AspNetCore.Identity;

namespace JWTTokenSample.Entities.Models
{
    public class User : IdentityUser
	{
		public string? RefreshToken { get; set; }
		public DateTime RefreshTokenExpiryTime { get; set; }
	}
}
