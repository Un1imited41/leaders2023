package com.hakaton.enterprise_investment.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.Principal;
import java.util.Set;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Table(name = "user_info")
public class UserInfo implements Principal {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sq_user_info")
    @SequenceGenerator(name = "sq_user_info", sequenceName = "sq_user_info_id", allocationSize = 0)
    private Long id;
    private String sub;
    private String email;
    private String clientRegistrationId;

    @Embedded
    private UserDetails userDetails;

    private boolean isPropertyManager;

    @Transient
    private Set<String> roles;

    public UserInfo(String email, String clientRegistrationId) {
        this.email = email;
        this.clientRegistrationId = clientRegistrationId;
    }

    public UserInfo(Long id) {
        this.id = id;
    }

    @Override
    public String getName() {
        return email;
    }

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }
}
