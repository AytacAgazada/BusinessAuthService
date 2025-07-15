package com.example.businessauthservice.model.dto;

import com.example.businessauthservice.model.enumeration.Roles;
import jakarta.validation.constraints.*;
import lombok.Data;

@Data

public class Signup {

    @NotBlank(message = "Username cannot be blank")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String userName;

    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Email must be a valid email address")
    private String email;

    @NotBlank(message = "Password cannot be blank")
    @Pattern(
            regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{8,}$",
            message = "Password must be at least 8 characters long and contain an uppercase letter, a lowercase letter, a digit, and a special character (!@#$%^&*()_+)."
    )
    private String password;

    @NotBlank(message = "Role cannot be blank")
    @Pattern(regexp = "USER|BUSINESS_OWNER", message = "Invalid role selected. Must be USER or BUSINESS_OWNER.")
    private String selectedRole;

}
