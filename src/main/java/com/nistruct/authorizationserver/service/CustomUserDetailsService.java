package com.nistruct.authorizationserver.service;

import com.nistruct.authorizationserver.dao.OAuthDAOService;
import com.nistruct.authorizationserver.model.CustomUser;
import com.nistruct.authorizationserver.model.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    OAuthDAOService oAuthDAOService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        try {
            UserEntity userEntity = oAuthDAOService.getUserDetails(username);
            if (userEntity != null && userEntity.getId() != null && !"".equalsIgnoreCase(userEntity.getId())) {
                CustomUser customUser = new CustomUser(userEntity);
                return customUser;
            }
        } catch (Exception e) {
            throw new UsernameNotFoundException("User " + username + "was not found in the database");
        }

        return null;
    }
}
