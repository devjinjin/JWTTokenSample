namespace JWTTokenSample.Shared.DTO.Account
{
    public class ResetPasswordResponseDto
	{
		public bool IsResetPasswordSuccessful { get; set; }
		public IEnumerable<string>? Errors { get; set; }
	}
}
