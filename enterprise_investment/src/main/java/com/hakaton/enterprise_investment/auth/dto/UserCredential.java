package com.hakaton.enterprise_investment.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record UserCredential(@Email String email, @NotBlank String password) {
}
