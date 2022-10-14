using System.ComponentModel.DataAnnotations;

namespace JWTTokenSample.Shared.DTO.Account
{
    public class ForgotPasswordDto
	{
		[Required]
		[EmailAddress]
		public string? Email { get; set; }
		public string? ClientURI { get; set; }
	}
}
