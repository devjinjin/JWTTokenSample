namespace JWTTokenSample.Shared.DTO.Account
{
    public record RegisterResultDto
    {
        public string ConfirmType { get; set; } = "Email";

        public string? GoogleOTPKey { get; set; }

        public string? GoogleOTPSecretKey { get; set; }
    }
}
