package com.hakaton.enterprise_investment.auth.converter;

import com.hakaton.enterprise_investment.auth.util.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Component
public class JwtAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String ROLE_KEY = "roles";

    @Value("${app-config.default-registration-id}")
    private String defaultClientRegistrationId;

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        final var clientId = JwtUtils.extractClientId(source);
        if (Objects.equals(defaultClientRegistrationId, clientId)) {
            return ((List<String>) source.getClaims().get(ROLE_KEY)).stream()
                    .map(SimpleGrantedAuthority::new)
                    .map(e -> (GrantedAuthority) e)
                    .toList();
        }
        return Collections.emptyList();
    }
}
