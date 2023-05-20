package com.hakaton.enterprise_investment.auth.util;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

public class JwtUtils {

    public static final String AUDIENCE_KEY = "aud";

    public static String extractClientId(Jwt jwt) {
        final var aud = jwt.getClaims().get(AUDIENCE_KEY);
        if (aud instanceof List clients) {
            return (String) clients.stream().findFirst().orElse("");
        }
        return "";
    }
}

