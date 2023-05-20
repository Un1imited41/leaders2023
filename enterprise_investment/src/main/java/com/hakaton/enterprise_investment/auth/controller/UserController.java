package com.hakaton.enterprise_investment.auth.controller;

import com.hakaton.enterprise_investment.auth.entity.UserInfo;
import com.hakaton.enterprise_investment.auth.service.UserInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("user")
@RequiredArgsConstructor
// todo remove localhost:4200
@CrossOrigin(origins = {"${app-config.frontend}", "http://localhost:4200"}, allowCredentials = "true")
@Validated
public class UserController {

    private final UserInfoService userInfoService;

    @GetMapping("/info")
    public UserInfo getCurrentUser() {
        return userInfoService.getCurrentUser();
    }

    @GetMapping("/token/revoke")
    public void revokeAllTokens() {
        userInfoService.revokeAllTokens();
    }

//    @GetMapping("/email/verification/request")
//    public void sendEmailVerificationRequest() {
//        userInfoService.sendEmailVerificationRequest();
//    }
}
