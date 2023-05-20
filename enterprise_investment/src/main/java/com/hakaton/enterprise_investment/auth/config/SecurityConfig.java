package com.hakaton.enterprise_investment.auth.config;

import com.hakaton.enterprise_investment.auth.converter.UserInfoAuthConverter;
import com.hakaton.enterprise_investment.auth.entity.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Autowired
    private UserInfoAuthConverter userInfoAuthConverter;

    @Bean
    @Order(50)
    public SecurityFilterChain securityFilterConfig(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .securityMatcher("/user/**", "/auth/**", "/actuator/**")
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(c -> c.requestMatchers("/user/**").authenticated())
                .authorizeHttpRequests(c -> c.requestMatchers("/auth/**", "/actuator/**").permitAll())
                .oauth2ResourceServer(c -> c.jwt(j -> j.jwtAuthenticationConverter(userInfoAuthConverter)));
        return http.build();
    }

    @Bean
    @Scope("prototype")
    public UserInfo userDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getPrincipal() instanceof UserInfo userInfo) {
                return userInfo;
            }
        }
        return null;
    }
}