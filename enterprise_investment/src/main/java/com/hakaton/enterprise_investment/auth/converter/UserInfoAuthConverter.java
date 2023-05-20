package com.hakaton.enterprise_investment.auth.converter;

import com.hakaton.enterprise_investment.auth.repository.UserInfoRepository;
import com.hakaton.enterprise_investment.auth.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.ReflectionUtils;

import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class UserInfoAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtAuthenticationConverter jwtConverter;
    private final UserInfoRepository userInfoRepository;

    private static final String ROLE_PREFIX = "ROLE_";

    @Override
    public AbstractAuthenticationToken convert(Jwt source) {
        final var authToken = (JwtAuthenticationToken) jwtConverter.convert(source);
        final var userInfo = userInfoRepository
                .findByEmailAndClientRegistrationId(authToken.getName(), JwtUtils.extractClientId(source)).orElse(null);
        final var principalField = ReflectionUtils.findField(JwtAuthenticationToken.class, "principal");
        principalField.setAccessible(true);
        ReflectionUtils.setField(principalField, authToken, userInfo);
        if (userInfo != null) {
            final var roles = authToken.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .map(role -> role.replace(ROLE_PREFIX, "")).collect(Collectors.toSet());
            userInfo.setRoles(roles);
        }
        return authToken;
    }
}
