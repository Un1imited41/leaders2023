package com.hakaton.enterprise_investment.auth.mapper;

import com.hakaton.enterprise_investment.auth.dto.UserInfoDto;
import com.hakaton.enterprise_investment.auth.entity.UserInfo;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class UserMapper {

    @Value("${app-config.default-registration-id}")
    private String defaultClientRegistrationId;

    private final ModelMapper modelMapper = new ModelMapper();

    public UserInfo mapDefault(UserInfoDto userInfoDto) {
        final var userInfo = modelMapper.map(userInfoDto, UserInfo.class);
        userInfo.setClientRegistrationId(defaultClientRegistrationId);
        return userInfo;
    }

    public UserInfoDto mapToDto(UserInfo userInfo) {
        return modelMapper.map(userInfo, UserInfoDto.class);
    }

    public UserInfoDto mapToDto(UserInfo userInfo, List<String> roles) {
        final var userInfoDto = mapToDto(userInfo);
        userInfoDto.setRoles(roles);
        return userInfoDto;
    }
}
