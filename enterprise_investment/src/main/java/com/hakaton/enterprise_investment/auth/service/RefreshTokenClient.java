package com.hakaton.enterprise_investment.auth.service;

import com.hakaton.enterprise_investment.auth.dto.TokenResponse;
import com.hakaton.enterprise_investment.auth.util.OAuth2AutorizationUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.integration.support.locks.DefaultLockRegistry;
import org.springframework.integration.support.locks.LockRegistry;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;

@Service
public class RefreshTokenClient {

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final RestTemplate restTemplate;
    private final LockRegistry lockRegistry = new DefaultLockRegistry();

    public static final String TOKEN_KEY_PREFIX = "RefreshToken:";

    private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

    @Value("${app-config.default-registration-id}")
    private String defaultClientRegistrationId;

    public RefreshTokenClient(ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.restTemplate = new RestTemplate(
                List.of(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
        this.restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    }

    public TokenResponse getTokenResponse(String refreshToken) {
        final var tokenLock = lockRegistry.obtain(TOKEN_KEY_PREFIX + refreshToken);
        TokenResponse tokenResponse;
        try {
            tokenLock.lock();
            final var authToken = getTokenResponseInternal(refreshToken);
            return new TokenResponse(authToken.getAccessToken(), authToken.getRefreshToken(), authToken.getAdditionalParameters());
        } finally {
            tokenLock.unlock();
        }
    }

    private OAuth2AccessTokenResponse getTokenResponseInternal(String refreshToken) {
        //todo retrieve reg id from db or whatever
        final var clientRegistration = clientRegistrationRepository.findByRegistrationId(defaultClientRegistrationId);
        final var uri = UriComponentsBuilder
                .fromUriString(clientRegistration.getProviderDetails().getTokenUri())
                .build().toUri();
        final var parameters = prepareParameters(clientRegistration, refreshToken);
        final var headers = OAuth2AutorizationUtils.getTokenRequestHeaders(clientRegistration);
        final var request = new RequestEntity<>(parameters, headers, HttpMethod.POST, uri);
        return getResponse(request).getBody();
    }

    private MultiValueMap<String, String> prepareParameters(ClientRegistration clientRegistration, String refreshToken) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        parameters.add(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken);
        if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())) {
            parameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
            parameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
        }
        return parameters;
    }

    private ResponseEntity<OAuth2AccessTokenResponse> getResponse(RequestEntity<?> request) {
        try {
            return this.restTemplate.exchange(request, OAuth2AccessTokenResponse.class);
        } catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_TOKEN_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
                            + ex.getMessage(),
                    null);
            throw new OAuth2AuthorizationException(oauth2Error, ex);
        }
    }

}
