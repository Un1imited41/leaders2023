package com.hakaton.enterprise_investment.auth.controller;

import com.hakaton.enterprise_investment.auth.dto.TokenResponse;
import com.hakaton.enterprise_investment.auth.dto.UserCredential;
import com.hakaton.enterprise_investment.auth.dto.UserInfoDto;
import com.hakaton.enterprise_investment.auth.service.PasswordTokenClient;
import com.hakaton.enterprise_investment.auth.service.RefreshTokenClient;
import com.hakaton.enterprise_investment.auth.service.UserInfoService;
import jakarta.servlet.ServletContext;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Validated
// todo remove localhost:4200
@CrossOrigin(origins = {"${app-config.frontend}", "http://localhost:4200"}, allowCredentials = "true")
public class AuthController {

    private final UserInfoService userInfoService;
    private final PasswordTokenClient passwordTokenClient;
    private final RefreshTokenClient refreshTokenClient;
    private final ServletContext servletContext;

    @PostMapping("/user")
    public TokenResponse register(@Valid @RequestBody UserInfoDto userInfoDto) {
        userInfoService.register(userInfoDto);
        return passwordTokenClient.getTokenResponse(new UserCredential(userInfoDto.getEmail(), userInfoDto.getPassword()));
    }

    @PutMapping("/user")
    public ResponseEntity<TokenResponse> logon(@Valid @RequestBody UserCredential userCredential) {
        final var tokenResponse = passwordTokenClient.getTokenResponse(userCredential);
        final var refreshTokenCookie = createCookie(tokenResponse.getRefreshToken().getTokenValue());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(tokenResponse);
    }

    @GetMapping("/user/refresh-token")
    public ResponseEntity<TokenResponse> refreshToken(@CookieValue("refreshToken") String token) {
        final var tokenResponse = refreshTokenClient.getTokenResponse(token);
        final ResponseCookie refreshTokenCookie = createCookie(tokenResponse.getRefreshToken().getTokenValue());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString())
                .body(tokenResponse);
    }

    private ResponseCookie createCookie(String refreshToken) {
        return ResponseCookie
                .from("refreshToken", refreshToken)
                .path(servletContext.getContextPath() + "/auth/user/refresh-token")
                //todo secure
                .secure(false)
                .maxAge(Duration.ofDays(99999))
                .httpOnly(true)
                .build();
    }
}
