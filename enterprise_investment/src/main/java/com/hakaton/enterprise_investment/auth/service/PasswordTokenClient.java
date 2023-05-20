package com.hakaton.enterprise_investment.auth.service;

import com.hakaton.enterprise_investment.auth.dto.TokenResponse;
import com.hakaton.enterprise_investment.auth.dto.UserCredential;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PasswordTokenClient {

    private final DefaultPasswordTokenResponseClient delegate = new DefaultPasswordTokenResponseClient();
    private final ClientRegistration passwordClientRegistration;

    public TokenResponse getTokenResponse(UserCredential userCredential) {
        final var request = new OAuth2PasswordGrantRequest(
                passwordClientRegistration,
                userCredential.email(),
                userCredential.password()
        );

        final var authToken = delegate.getTokenResponse(request);
        return new TokenResponse(authToken.getAccessToken(), authToken.getRefreshToken(), authToken.getAdditionalParameters());
    }

}
