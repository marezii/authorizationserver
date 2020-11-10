package com.nistruct.authorizationserver.model;

import lombok.Data;

import java.security.KeyPair;
import java.util.Calendar;

@Data
public class KeyPairContainer {

    private String keyId;
    private KeyPair keyPair;

    private final Long expiredAt;

    public KeyPairContainer(String keyId, KeyPair keyPair, Long secondsExpiredAfter) {
        this.keyId = keyId;
        this.keyPair = keyPair;

        Long currentSeconds = getLocalTimeInSeconds();

        this.expiredAt = currentSeconds + secondsExpiredAfter;
    }

    public boolean isExpired() {
        Long currentSeconds = getLocalTimeInSeconds();
        return currentSeconds > expiredAt;
    }

    private long getLocalTimeInSeconds() {
        return Calendar.getInstance().getTimeInMillis() / 1000;
    }

}
