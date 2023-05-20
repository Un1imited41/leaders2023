package com.hakaton.enterprise_investment.auth.service;

import com.hakaton.enterprise_investment.auth.dto.UserCredential;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

@Service
public class AuthServerClient {

    private final RestTemplate restTemplate;

    public AuthServerClient(@Value("${app-config.auth-server}") URI authServer,
                            @Value("${spring.security.oauth2.client.registration.inner-client.client-id}") String clientId,
                            @Value("${spring.security.oauth2.client.registration.inner-client.client-secret}") String clientSecret) {
        this.restTemplate = new RestTemplateBuilder()
                .basicAuthentication(clientId, clientSecret)
                .rootUri(authServer.toString())
                .build();
    }

    public ResponseEntity<Object> createUser(UserCredential userCredential) {
        return restTemplate.postForEntity("/auth/user", userCredential, Object.class);
    }

    public ResponseEntity<Object> resetPassword(UserCredential userCredential) {
        return restTemplate.exchange("/auth/user/reset-password", HttpMethod.PUT, new HttpEntity<>(userCredential), Object.class);
    }

    public void addUserToGroup(String email, String groupName) {
        final var params = Map.of("email", email, "groupName", groupName);
        restTemplate.getForEntity(
                UriComponentsBuilder.fromPath("/auth/user/{email}/group/{groupName}").buildAndExpand(params).toUriString(),
                Object.class
        );
    }

    public void revokeAllTokens(String email) {
        final var params = Collections.singletonMap("email", email);
        restTemplate.getForEntity(
                UriComponentsBuilder.fromPath("/auth/user/{email}/token/revoke").buildAndExpand(params).toUriString(),
                Object.class
        );
    }
}
