namespace JWTTokenSample.Shared.DTO.TwoFactor
{
    public class GoogleTwoFactorSetupDto
    {
        public string? SharedKey { get; set; }

        public string? AuthenticatorUri { get; set; }
    }
}
