package com.nistruct.authorizationserver.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class JwkExposedModel {

    private String kid;
    private String kty;
    private String use;
    private String n;
    private String e;

}
