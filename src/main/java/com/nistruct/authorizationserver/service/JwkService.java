package com.nistruct.authorizationserver.service;

import com.nistruct.authorizationserver.model.JwkExposedModel;
import com.nistruct.authorizationserver.model.KeyPairContainer;

import java.security.KeyPair;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface JwkService {

    List<JwkExposedModel> findAllKeys() throws Exception;

    Optional<KeyPair> returnKeyPair() throws Exception;

    Set<KeyPairContainer> getCachedKeyPairs();

    String setKid() throws Exception;

    void setKeyPairExpiration(Long keyPairExpiration);

    void populateCache() throws Exception;

    KeyPair generateNewKeyPair() throws Exception;

}
