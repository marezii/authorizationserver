package com.nistruct.authorizationserver.service;

import com.nistruct.authorizationserver.model.JwkExposedModel;
import com.nistruct.authorizationserver.model.KeyPairContainer;

import java.security.KeyPair;
import java.util.Optional;
import java.util.Set;

public interface JwkService {

    Optional<KeyPair> returnKeyPair() throws Exception;

    Set<KeyPairContainer> getCachedKeyPairs(); //Iskoristicemo ga da vraca u zavisnosti od role

    Set<JwkExposedModel> getJwks();

    String setKid() throws Exception;

    void populateCache() throws Exception;

}
