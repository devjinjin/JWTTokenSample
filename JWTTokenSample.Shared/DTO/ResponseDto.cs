namespace JWTTokenSample.Shared.DTO
{
    public class ResponseDto
	{
		public bool IsSuccessfulRegistration { get; set; }
		public IEnumerable<string>? Errors { get; set; }
	}
}
