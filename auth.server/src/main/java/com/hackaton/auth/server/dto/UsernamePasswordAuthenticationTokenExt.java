package com.hackaton.auth.server.dto;

import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

public class UsernamePasswordAuthenticationTokenExt extends UsernamePasswordAuthenticationToken {

    @Getter
    private final OAuth2ClientAuthenticationToken clientToken;

    public UsernamePasswordAuthenticationTokenExt(Object principal, Object credentials, OAuth2ClientAuthenticationToken clientToken) {
        super(principal, credentials);
        this.clientToken = clientToken;
    }

}
