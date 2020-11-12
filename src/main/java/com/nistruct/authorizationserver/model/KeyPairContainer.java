package com.nistruct.authorizationserver.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.KeyPair;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class KeyPairContainer {

    private String keyId;
    private KeyPair keyPair;
    private String role;
}
