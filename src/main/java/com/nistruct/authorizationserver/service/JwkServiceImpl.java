package com.nistruct.authorizationserver.service;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nistruct.authorizationserver.dao.JwkExposedModelRepository;
import com.nistruct.authorizationserver.model.JwkExposedModel;
import com.nistruct.authorizationserver.model.KeyPairContainer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwkServiceImpl implements JwkService {

    private final Set<KeyPairContainer> cachedKeyPairs = new HashSet<>();

    private final JwkExposedModelRepository jwkExposedModelRepository;

    private Long keyPairExpiration = 120L;

    private static final int KEYPAIRNo = 2;

    @PostConstruct
    public void init() {
        try {
            returnKeyPair();
        } catch (Exception e) {
            log.warn("Unable to initialize local key pairs.", e);
        }
    }

    @Override
    @Transactional
    public List<JwkExposedModel> findAllKeys() throws Exception {
        List<JwkExposedModel> result = new ArrayList<>();
        Iterable<JwkExposedModel> allJwks = jwkExposedModelRepository.findAll();
        allJwks.forEach(result::add);

        return result;
    }

    @Override
    @Transactional
    public Optional<KeyPair> returnKeyPair() throws Exception {
        log.info("Retrieving available RSA KeyPair...");
        cachedKeyPairs.removeIf(keyPairContainer -> keyPairContainer.isExpired());

        log.debug("available keys:{}", cachedKeyPairs);
        populateCache();

        Optional<KeyPairContainer> optionalKeyPairContainer =
                cachedKeyPairs
                        .stream()
                        .filter(keyPairContainer
                                -> !keyPairContainer.isExpired()).findAny();

        log.debug("Key found: {}", optionalKeyPairContainer);
        return Optional
                .ofNullable(optionalKeyPairContainer.isPresent() ? optionalKeyPairContainer.get().getKeyPair() : null);
    }

    @Override
    public Set<KeyPairContainer> getCachedKeyPairs() {
        return this.cachedKeyPairs;
    }

    @Override
    public String setKid() throws Exception {
        KeyPair keyPair = returnKeyPair().orElseThrow(() -> new Exception("Unable to obtain a valid RSA KeyPair"));

        return cachedKeyPairs
                .stream().filter(ckp -> ckp.getKeyPair().equals(keyPair)).findAny().get().getKeyId();
    }

    @Override
    public void setKeyPairExpiration(Long keyPairExpiration) {
        this.keyPairExpiration = keyPairExpiration;

    }

    @Override
    @Transactional
    public void populateCache() throws Exception {
        while (cachedKeyPairs.size() < KEYPAIRNo) {

            //Generate a new KeyPair
            KeyPair keyPair = generateNewKeyPair();
            String keyId = UUID.randomUUID().toString();

            KeyPairContainer keyPairContainer = new KeyPairContainer(keyId, keyPair, keyPairExpiration);

            //Generate JWK
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(keyId)
                    .build();

            JwkExposedModel jem = new JwkExposedModel();
            jem.setKid(keyId);
            jem.setKty(rsaKey.getKeyType().getValue());
            jem.setUse(rsaKey.getKeyUse().getValue());
            jem.setN(rsaKey.getModulus().toString());
            jem.setE(rsaKey.getPublicExponent().toString());
            jem.setExp(keyPairContainer.getExpiredAt());

            //Save JWK
            jwkExposedModelRepository.save(jem);

            //Store in local cache
            cachedKeyPairs.add(keyPairContainer);
        }
    }

    @Override
    public KeyPair generateNewKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize(2048, SecureRandom.getInstanceStrong());

            return keyPairGenerator.generateKeyPair();

        } catch (Exception e) {
            log.error("Unable to generate new RSA Key pair", e);
            throw new Exception(e);
        }
    }
}
