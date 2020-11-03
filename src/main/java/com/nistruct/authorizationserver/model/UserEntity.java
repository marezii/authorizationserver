package com.nistruct.authorizationserver.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;

@Getter
@Setter
public class UserEntity {

    private String id;
    private String name;
    private String emailId;
    private String password;
    private Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

}
