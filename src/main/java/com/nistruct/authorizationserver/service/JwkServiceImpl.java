package com.nistruct.authorizationserver.service;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nistruct.authorizationserver.config.Keys;
import com.nistruct.authorizationserver.model.JwkExposedModel;
import com.nistruct.authorizationserver.model.KeyPairContainer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@ConfigurationProperties(prefix = "myvariables")
public class JwkServiceImpl implements JwkService {

    private Map<String, Map<String, String>> keys;

    private List<Keys> keysList = new ArrayList<>();

    private final Set<KeyPairContainer> cachedKeyPairs = new HashSet<>();

    private final Set<JwkExposedModel> jwks = new HashSet<>();

    private final JdbcTemplate jdbcTemplate;

    private static final int KEYPAIRNo = 3;

    private List<String> kids;

    @PostConstruct
    public void init() {
        try {
            getKeysFromYAML();
            populateCache();
        } catch (Exception e) {
            log.warn("Unable to initialize local key pairs.", e);
        }
    }

    private void getKeysFromYAML() {
        List<String> keysList = keys.keySet().stream().collect(Collectors.toList());
        List<Map<String, String>> valuesMap = keys.values().stream().collect(Collectors.toList());
        for(int i = 0; i < keys.size(); i++){
            Keys keys = new Keys();
            keys.setRole(keysList.get(i));
            keys.setKey(valuesMap.get(i).get("key"));
            keys.setPrivateKey(valuesMap.get(i).get("privateKey"));
            keys.setPublicKey(valuesMap.get(i).get("publicKey"));
            this.keysList.add(keys);
        }
    }

    public Map<String, Map<String, String>> getKeys() {
        return keys;
    }

    public void setKeys(Map<String, Map<String, String>> keys) {
        this.keys = keys;
    }

    public List<String> getKids() {
        return kids;
    }

    public void setKids(List<String> kids) {
        this.kids = kids;
    }

    @Override
    public Set<JwkExposedModel> getJwks() {
        return this.jwks;
    }


    @Override
    public Set<KeyPairContainer> getCachedKeyPairs() {
        return this.cachedKeyPairs;
    }

    @Override
    public Optional<KeyPair> returnKeyPair() throws Exception {
        //todo ovde ce da se vraca u zavisnosti od role...
        Optional<KeyPairContainer> optionalKeyPairContainer =
                cachedKeyPairs
                        .stream()
                        .findFirst();

        return Optional
                .ofNullable(optionalKeyPairContainer.isPresent() ? optionalKeyPairContainer.get().getKeyPair() : null);
    }

    @Override
    public String setKid() throws Exception {
        KeyPair keyPair = returnKeyPair().orElseThrow(() -> new Exception("Unable to obtain a valid RSA KeyPair"));

        return cachedKeyPairs.stream()
                .filter(ckp -> ckp.getKeyPair().equals(keyPair))
                .findAny()
                .get()
                .getKeyId();
    }

    @Override
    @Transactional
    public void populateCache() throws Exception {

        List<String> roles = getRoles();

        while (cachedKeyPairs.size() < KEYPAIRNo) {
            RSAPrivateKey privateKey = getRsaPrivateKey();

            RSAPublicKey publicKey = getRsaPublicKey();

            //Generate a new KeyPair
            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            String keyId = keysList.get(cachedKeyPairs.size()).getKey();

            KeyPairContainer keyPairContainer =
                    new KeyPairContainer(keyId, keyPair, "ROLE_" + keysList.get(cachedKeyPairs.size()).getRole().toUpperCase());

            //Generate JWK
            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(keyId)
                    .build();

            JwkExposedModel jem = new JwkExposedModel();
            jem.setKid(keyId);
            jem.setKty(rsaKey.getKeyType().getValue());
            jem.setUse(rsaKey.getKeyUse().getValue());
            jem.setN(rsaKey.getModulus().toString());
            jem.setE(rsaKey.getPublicExponent().toString());

            //Save jwks
            jwks.add(jem);

            //Store in local cache
            cachedKeyPairs.add(keyPairContainer);
        }
    }

    private List<String> getRoles() {
        List<String> list = jdbcTemplate.query("SELECT * FROM ROLE",
                (ResultSet rs, int rowNum) -> {
                    String role = rs.getString("ROLE_NAME");
                    return role;
                });
        return list;
    }

    private RSAPublicKey getRsaPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Public Key from PEM file
        String publicKeyPEM = keysList.get(cachedKeyPairs.size()).getPublicKey()
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.decodeBase64(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    private RSAPrivateKey getRsaPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Private Key from PEM file
        String privateKeyPEM = keysList.get(cachedKeyPairs.size()).getPrivateKey()
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encodedPrivate = Base64.decodeBase64(privateKeyPEM);

        KeyFactory keyFactoryPrivate = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(encodedPrivate);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactoryPrivate.generatePrivate(keySpecPrivate);
        return privateKey;
    }

}
