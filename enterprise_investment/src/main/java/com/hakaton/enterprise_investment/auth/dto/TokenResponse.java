package com.hakaton.enterprise_investment.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.io.Serializable;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenResponse implements Serializable {

    private OAuth2AccessToken accessToken;
    private OAuth2RefreshToken refreshToken;
    private Map<String, Object> additionalParameters;

}
