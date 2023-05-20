package com.hackaton.auth.server.converter;

import com.hackaton.auth.server.dto.UsernamePasswordAuthenticationTokenExt;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import javax.servlet.http.HttpServletRequest;

public class UsernamePasswordClientAuthenticationConverter implements AuthenticationConverter {

    private final AuthenticationConverter clientConverter = new ClientSecretBasicAuthenticationConverter();

    @Override
    public Authentication convert(HttpServletRequest request) {
        final var username = request.getParameter("username");
        if (username == null) {
            return null;
        }

        final var password = request.getParameter("password");
        if (password == null) {
            return null;
        }

        final var authentication = clientConverter.convert(request);
        if (authentication == null) {
            return null;
        }

        return new UsernamePasswordAuthenticationTokenExt(username, password, (OAuth2ClientAuthenticationToken) authentication);
    }
}
