package com.nistruct.authorizationserver.controller;


import com.nistruct.authorizationserver.service.JwkService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestController
public class JwkSetController {

    private static final String JWK_SET_URI = "/.well-known/jwks";

    private final JwkService jwkService;

    @GetMapping(JWK_SET_URI)
    @ResponseStatus(HttpStatus.OK)
    public Map<String, ?> getAvailableJwk() throws Exception{
        log.debug("Retrieving available JWK...");
        Map<String, Object> response = new HashMap<>();

        response.put("keys", jwkService.getJwks());

        log.debug("public Keys successfully retrieved...");

        return response;
    }
}
