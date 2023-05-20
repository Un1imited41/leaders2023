package com.hakaton.enterprise_investment.auth.entity;

import jakarta.persistence.Embeddable;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Embeddable
@Getter
@Setter
@NoArgsConstructor
public class UserDetails {

    private String firstname;
    private String lastname;
    private String citizenship;
    private LocalDate birthDate;

}
