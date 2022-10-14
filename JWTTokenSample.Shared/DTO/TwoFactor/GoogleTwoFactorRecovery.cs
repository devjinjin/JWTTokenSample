using System.ComponentModel.DataAnnotations;

namespace JWTTokenSample.Shared.DTO.TwoFactor
{
    public class GoogleTwoFactorRecovery
    {
        [Required]
        [DataType(DataType.EmailAddress)]
        public string? Email { get; set; }

        [Required]
        [DataType(DataType.Text)]
        [Display(Name = "Recovery Code")]
        public string? RecoveryCode { get; set; }
    }
}
