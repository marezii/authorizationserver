package com.nistruct.authorizationserver.dao;

import com.nistruct.authorizationserver.model.UserEntity;

public interface OAuthDAOService {

    public UserEntity getUserDetails(String emailId);
}
