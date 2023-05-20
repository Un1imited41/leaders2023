package com.hackaton.auth.server.config;

import com.hackaton.auth.server.service.JdbcOAuth2AuthorizationServiceExt;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration
public class UserAuthConfig {

    @Bean
    public JdbcOAuth2AuthorizationServiceExt jdbcOAuth2AuthorizationServiceExt(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationServiceExt(jdbcTemplate, registeredClientRepository);
    }
}