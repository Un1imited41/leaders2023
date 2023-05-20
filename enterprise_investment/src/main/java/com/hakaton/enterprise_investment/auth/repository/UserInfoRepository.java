package com.hakaton.enterprise_investment.auth.repository;


import com.hakaton.enterprise_investment.auth.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepository extends JpaRepository<UserInfo, String> {

    Optional<UserInfo> findByEmailAndClientRegistrationId(String email, String clientRegistrationId);

    boolean existsByEmail(String email);

}

