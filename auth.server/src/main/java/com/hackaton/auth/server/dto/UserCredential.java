package com.hackaton.auth.server.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

public record UserCredential(@Email String email, @NotBlank String password) {
}
