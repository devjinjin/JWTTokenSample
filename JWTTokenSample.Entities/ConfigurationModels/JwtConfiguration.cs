namespace JWTTokenSample.Entities.ConfigurationModels
{
    public class JwtConfiguration
	{
		public string Section { get; set; } = "JwtSettings";

#pragma warning disable CS8632 // nullable 참조 형식에 대한 주석은 코드에서 '#nullable' 주석 컨텍스트 내에만 사용되어야 합니다.
		public string? ValidIssuer { get; set; }

		public string? ValidAudience { get; set; }

		public string ValidSecretKey { get; set; }

		public string? Expires { get; set; }

#pragma warning restore CS8632 // nullable 참조 형식에 대한 주석은 코드에서 '#nullable' 주석 컨텍스트 내에만 사용되어야 합니다.

	}
}
