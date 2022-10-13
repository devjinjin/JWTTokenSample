namespace JWTTokenSample.Shared.DTO
{
    public class ResetPasswordResponseDto
	{
		public bool IsResetPasswordSuccessful { get; set; }
		public IEnumerable<string>? Errors { get; set; }
	}
}
