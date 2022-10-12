﻿using System.ComponentModel.DataAnnotations;

namespace JWTTokenSample.Shared.DTO
{
    public class UserForRegistrationDto
	{
		[Required(ErrorMessage = "Email is required.")]
		public string? Email { get; set; }
		[Required(ErrorMessage = "Password is required.")]
		public string? Password { get; set; }
		[Compare(nameof(Password),
			ErrorMessage = "The password and confirmation password do not match.")]
		public string? ConfirmPassword { get; set; }
		public string? ClientURI { get; set; }

	}
}