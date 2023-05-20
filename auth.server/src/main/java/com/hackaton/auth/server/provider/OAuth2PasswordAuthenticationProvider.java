package com.hackaton.auth.server.provider;

import com.hackaton.auth.server.dto.UsernamePasswordAuthenticationTokenExt;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.context.ProviderContext;
import org.springframework.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.util.LinkedHashMap;
import java.util.Set;

import static org.springframework.security.oauth2.core.oidc.OidcScopes.OPENID;

@Slf4j
public class OAuth2PasswordAuthenticationProvider implements AuthenticationProvider {


    private final DaoAuthenticationProvider daoAuthProvider;
    private final OAuth2AuthorizationCodeRequestAuthenticationProvider codeRequestAuthenticationProvider;
    private final ClientSecretAuthenticationProvider clientSecretAuthenticationProvider;
    private final OAuth2AuthorizationCodeAuthenticationProvider oAuth2AuthorizationCodeAuthenticationProvider;
    private final ProviderSettings providerSettings;


    public OAuth2PasswordAuthenticationProvider(DaoAuthenticationProvider daoAuthenticationProvider,
                                                OAuth2AuthorizationService authorizationService,
                                                RegisteredClientRepository registeredClientRepository,
                                                OAuth2AuthorizationConsentService consentService,
                                                OAuth2TokenGenerator<Jwt> defaultTokenGenerator,
                                                ProviderSettings providerSettings) {
        this.providerSettings = providerSettings;
        this.daoAuthProvider = daoAuthenticationProvider;
        this.clientSecretAuthenticationProvider = new ClientSecretAuthenticationProvider(registeredClientRepository, authorizationService);
        this.codeRequestAuthenticationProvider = new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository,
                authorizationService, consentService);
        this.oAuth2AuthorizationCodeAuthenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(authorizationService,
                new DelegatingOAuth2TokenGenerator(
                        defaultTokenGenerator,
                        new OAuth2RefreshTokenGenerator()
                ));
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {

            final var custom = (UsernamePasswordAuthenticationTokenExt) authentication;
            final var principal = (UsernamePasswordAuthenticationToken) daoAuthProvider.authenticate(authentication);
            final var clientToken = (OAuth2ClientAuthenticationToken) clientSecretAuthenticationProvider.authenticate(custom.getClientToken());
            final var registeredClient = clientToken.getRegisteredClient();
            Assert.notNull(registeredClient, "Only non-client supported");

            final var redirectUri = registeredClient.getRedirectUris().stream().findFirst().orElse("");

            OAuth2AuthorizationCodeRequestAuthenticationToken requestAuthenticationToken =
                    OAuth2AuthorizationCodeRequestAuthenticationToken.with(registeredClient.getClientId(), principal)
                            .authorizationUri("no://op")
                            .consentRequired(false)
                            .scopes(Set.of(OPENID))
                            .redirectUri(redirectUri)
                            .state("STATE").build();

            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
                    (OAuth2AuthorizationCodeRequestAuthenticationToken) codeRequestAuthenticationProvider.authenticate(requestAuthenticationToken);

            OAuth2AuthorizationCodeAuthenticationToken codeToken = new OAuth2AuthorizationCodeAuthenticationToken(
                    authorizationCodeRequestAuthenticationResult.getAuthorizationCode().getTokenValue(), clientToken,
                    redirectUri, new LinkedHashMap<>());

            ProviderContextHolder.setProviderContext(new ProviderContext(providerSettings, null));

            return oAuth2AuthorizationCodeAuthenticationProvider.authenticate(codeToken);

        } catch (Exception e) {
            log.error("Password auth provider error", e);
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationTokenExt.class.isAssignableFrom(authentication);
    }
}
