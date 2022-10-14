using System.ComponentModel.DataAnnotations;

namespace JWTTokenSample.Shared.DTO.TwoFactor
{
    public class EmailTwoFactorDto
	{
		[Required]
		[DataType(DataType.EmailAddress)]
		public string? Email { get; set; }

		[Required(ErrorMessage = "Token is required")]
		public string? TwoFactorToken { get; set; }
	}
}
