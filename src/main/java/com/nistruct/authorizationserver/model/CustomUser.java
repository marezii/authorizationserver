package com.nistruct.authorizationserver.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.userdetails.User;

@Getter
@Setter
public class CustomUser extends User {

    private String id;
    private String name;

    public CustomUser(UserEntity userEntity) {
        super(userEntity.getEmailId(), userEntity.getPassword(), userEntity.getGrantedAuthorities());
        this.id = userEntity.getId();
        this.name = userEntity.getName();
    }
}
