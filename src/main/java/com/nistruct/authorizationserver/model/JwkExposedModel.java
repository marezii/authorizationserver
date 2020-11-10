package com.nistruct.authorizationserver.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@RedisHash(value = "Jwk") //, timeToLive = 120
public class JwkExposedModel {

    @Id
    private String kid;
    private String kty;
    private String use;
    private String n;
    private String e;
    private Long exp;

}
