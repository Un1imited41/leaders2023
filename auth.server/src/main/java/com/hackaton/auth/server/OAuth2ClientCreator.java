package com.hackaton.auth.server;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2ClientCreator implements ApplicationRunner {

    private final RegisteredClientRepository repository;
    private final ClientSetting clientSetting;

    @Override
    public void run(ApplicationArguments args) {
        if (repository.findByClientId(clientSetting.clientId) == null) {
            final var client = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientSetting.clientId)
                    .clientSecret("{noop}" + clientSetting.clientSecret)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                            .accessTokenTimeToLive(clientSetting.accessTokenTTL)
                            .refreshTokenTimeToLive(clientSetting.refreshTokenTTL)
                            .reuseRefreshTokens(clientSetting.reuseRefreshTokens)
                            .build())
                    //dummy uri
                    .redirectUri("http://127.0.0.1:8080")
                    .scope(OidcScopes.OPENID)
                    .build();
            repository.save(client);
        }
    }

    @ConfigurationProperties(prefix = "app-config.registered-client")
    record ClientSetting(String clientId, String clientSecret,
                         Duration refreshTokenTTL, Duration accessTokenTTL,
                         boolean reuseRefreshTokens) {
    }
}
