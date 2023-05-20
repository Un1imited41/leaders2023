package com.hakaton.enterprise_investment.auth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Configuration
@RequiredArgsConstructor
public class ClientRegistrationConfig {

    @Value("${app-config.default-registration-id}")
    private String defaultClientRegistrationId;

    @Bean
    public ClientRegistration passwordClientRegistration(ClientRegistrationRepository repository) {
        return ClientRegistration.withClientRegistration(defaultClientRegistration(repository))
                .authorizationGrantType(AuthorizationGrantType.PASSWORD).build();
    }

    @Bean
    public ClientRegistration defaultClientRegistration(ClientRegistrationRepository repository) {
        return repository.findByRegistrationId(defaultClientRegistrationId);
    }
}
