using System.ComponentModel.DataAnnotations;

namespace JWTTokenSample.Shared.DTO.TwoFactor
{
    public class EmailTwoFactorDto
	{
		public string? Email { get; set; }

		[Required(ErrorMessage = "Token is required")]
		public string? TwoFactorToken { get; set; }
	}
}
