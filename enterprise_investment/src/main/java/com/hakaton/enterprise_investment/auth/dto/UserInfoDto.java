package com.hakaton.enterprise_investment.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserInfoDto {

    private String sub;

    private String email;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String password;

    private String clientRegistrationId;
    private List<String> roles;

}
