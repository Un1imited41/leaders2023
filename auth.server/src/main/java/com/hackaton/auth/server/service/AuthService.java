package com.hackaton.auth.server.service;

import com.hackaton.auth.server.dto.UserCredential;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JdbcUserDetailsManager jdbcUserDetailsManager;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final JdbcOAuth2AuthorizationServiceExt jdbcAuthService;

    private final static String DEFAULT_AUTHORITY = "common";

    public void createUser(UserCredential userCredential) {
        jdbcUserDetailsManager.createUser(User.withUsername(userCredential.email())
                .passwordEncoder(passwordEncoder::encode)
                .password(userCredential.password())
                .authorities(DEFAULT_AUTHORITY)
                .disabled(false)
                .build());
    }

    public void resetPassword(UserCredential userCredential) {
        final var authentication = new UsernamePasswordAuthenticationToken(userCredential.email(), userCredential.password());
        final var origin = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        jdbcUserDetailsManager.changePassword("", passwordEncoder.encode(userCredential.password()));
        SecurityContextHolder.getContext().setAuthentication(origin);
    }

    public void addUserToGroup(String email, String groupName) {
        jdbcUserDetailsManager.addUserToGroup(email, groupName);
    }

    public void revokeAllTokens(String email) {
        jdbcAuthService.findByPrincipalName(email).forEach(jdbcAuthService::remove);
    }
}
