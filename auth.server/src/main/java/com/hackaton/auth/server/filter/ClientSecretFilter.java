package com.hackaton.auth.server.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Service
@RequiredArgsConstructor
public class ClientSecretFilter extends OncePerRequestFilter {

    private final ClientSecretAuthenticationProvider clientSecretAuthenticationProvider;
    private final ClientSecretBasicAuthenticationConverter clientSecretBasicAuthenticationConverter = new ClientSecretBasicAuthenticationConverter();
    public static final String PATH = "/auth/user";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        final var authentication = clientSecretBasicAuthenticationConverter.convert(request);
        if (authentication == null) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }
        try {
            clientSecretAuthenticationProvider.authenticate(authentication);
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().startsWith(PATH);
    }
}