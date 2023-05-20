package com.hackaton.auth.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.hackaton.auth.server.converter.UsernamePasswordClientAuthenticationConverter;
import com.hackaton.auth.server.provider.OAuth2PasswordAuthenticationProvider;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.ClientSecretAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
public class AuthorizationServerConfig {


    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      OAuth2PasswordAuthenticationProvider provider) throws Exception {
        applySecurity(http, provider);
        return http.build();
    }

    public void applySecurity(HttpSecurity http, OAuth2PasswordAuthenticationProvider OAuth2PasswordAuthenticationProvider) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer<>();

        authorizationServerConfigurer.addObjectPostProcessor(new ObjectPostProcessor<OAuth2TokenEndpointFilter>() {
            @Override
            public <O extends OAuth2TokenEndpointFilter> O postProcess(O tokenEndpointFilter) {
                tokenEndpointFilter.setAuthenticationConverter(new DelegatingAuthenticationConverter(
                        List.of(
                                new OAuth2AuthorizationCodeAuthenticationConverter(),
                                new OAuth2RefreshTokenAuthenticationConverter(),
                                new OAuth2ClientCredentialsAuthenticationConverter(),
                                new UsernamePasswordClientAuthenticationConverter()
                        )));
                return tokenEndpointFilter;
            }
        });
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

        final var builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.authenticationProvider(OAuth2PasswordAuthenticationProvider);


        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);
    }

    @Bean
    public OAuth2PasswordAuthenticationProvider passwordAuthProvider(DaoAuthenticationProvider daoAuthenticationProvider,
                                                                     OAuth2AuthorizationService authorizationService,
                                                                     RegisteredClientRepository repository,
                                                                     OAuth2AuthorizationConsentService consentService,
                                                                     ProviderSettings providerSettings) {
        return new OAuth2PasswordAuthenticationProvider(daoAuthenticationProvider, authorizationService, repository,
                consentService, defaultTokenGenerator(), providerSettings);
    }

    @Bean
    public DaoAuthenticationProvider defaultDaoAuthenticationProvider(UserDetailsService userDetailsService) {
        final var provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        return provider;
    }

    private OAuth2TokenGenerator<Jwt> defaultTokenGenerator() {
        final var encoder = new NimbusJwsEncoder(jwkSource());
        final var jwtGenerator = new JwtGenerator(encoder);
        jwtGenerator.setJwtCustomizer(defaultTokenCustomizer());
        return jwtGenerator;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> defaultTokenCustomizer() {
        return context -> context.getClaims().claim("roles", context.getPrincipal().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toList())).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate template) {
        return new JdbcRegisteredClientRepository(template);
    }

    @Bean
    public JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
        final var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.setEnableGroups(true);
        jdbcUserDetailsManager.setRolePrefix("ROLE_");
        return jdbcUserDetailsManager;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public ClientSecretAuthenticationProvider clientSecretAuthenticationProvider(RegisteredClientRepository registeredClientRepository,
                                                                                 OAuth2AuthorizationService authorizationService) {
        return new ClientSecretAuthenticationProvider(registeredClientRepository, authorizationService);
    }

    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    @SneakyThrows
    private static KeyPair generateRsaKey() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }


    @Bean
    public ProviderSettings providerSettings(@Value("${app-config.issuer}") String issuer) {
        return ProviderSettings.builder()
                .issuer(issuer)
                .build();
    }
}
