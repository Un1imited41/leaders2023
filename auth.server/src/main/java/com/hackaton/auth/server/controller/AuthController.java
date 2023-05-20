package com.hackaton.auth.server.controller;

import com.hackaton.auth.server.dto.UserCredential;
import com.hackaton.auth.server.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.text.MessageFormat;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/user")
    public ResponseEntity<Object> createUser(@Validated @RequestBody UserCredential userCredential) {
        try {
            authService.createUser(userCredential);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error(MessageFormat.format("New user {0} creation error", userCredential.email()), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PutMapping("/user/reset-password")
    public ResponseEntity<Object> resetPassword(@Validated @RequestBody UserCredential userCredential) {
        try {
            authService.resetPassword(userCredential);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error(MessageFormat.format("Reset password error for user: {0}", userCredential.email()), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/user/{email}/group/{groupName}")
    public ResponseEntity<Object> addUserToGroup(@PathVariable String email, @PathVariable String groupName) {
        try {
            authService.addUserToGroup(email, groupName);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error(MessageFormat.format("Error adding user to group: {0}, {1}", email, groupName), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/user/{email}/token/revoke")
    public ResponseEntity<Object> revokeAllTokens(@PathVariable String email) {
        try {
            authService.revokeAllTokens(email);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error(MessageFormat.format("Error revoking tokens: {0}", email), e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
