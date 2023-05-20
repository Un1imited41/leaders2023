package com.hakaton.enterprise_investment.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserDetailsDto {

    @NotBlank
    private String firstname;

    @NotBlank
    private String lastname;

    private String surname;

    private String organizationName;

    @NotBlank
    private String inn;

    private String websiteUrl;

    private Long industryId;

    private String country;
    private String city;

    private String jobTitle;

}
