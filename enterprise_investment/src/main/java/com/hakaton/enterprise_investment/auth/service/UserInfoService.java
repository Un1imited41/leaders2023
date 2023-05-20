package com.hakaton.enterprise_investment.auth.service;

import com.hakaton.enterprise_investment.auth.dto.UserCredential;
import com.hakaton.enterprise_investment.auth.dto.UserInfoDto;
import com.hakaton.enterprise_investment.auth.entity.UserDetails;
import com.hakaton.enterprise_investment.auth.entity.UserInfo;
import com.hakaton.enterprise_investment.auth.mapper.UserMapper;
import com.hakaton.enterprise_investment.auth.repository.UserInfoRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserInfoService {

    private final AuthServerClient authServerClient;
    private final UserInfoRepository userInfoRepository;
    private final ObjectProvider<UserInfo> userInfoProvider;
    private final UserMapper userMapper;

    @Transactional
    public void register(UserInfoDto newUser) {
        final var response = authServerClient.createUser(new UserCredential(newUser.getEmail(), newUser.getPassword()));
        if (response == null || !response.getStatusCode().is2xxSuccessful()) {
            throw new RuntimeException("Не удалось зарегистрировать пользователя");
        }
        final var userInfo = userMapper.mapDefault(newUser);
        userInfoRepository.save(userInfo);
    }

    public void revokeAllTokens() {
        final var user = userInfoProvider.getIfAvailable();
        authServerClient.revokeAllTokens(user.getEmail());
    }

    public UserInfo getCurrentUser() {
        return userInfoProvider.getIfAvailable();
    }

    private UserDetails getUserDetails(UserInfo userInfo) {
        var userDetails = userInfo.getUserDetails();
        if (userDetails == null) {
            userDetails = new UserDetails();
            userInfo.setUserDetails(userDetails);
        }
        return userDetails;
    }

    public boolean validateEmail(String email) {
        return !userInfoRepository.existsByEmail(email);
    }
}
