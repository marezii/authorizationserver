package com.nistruct.authorizationserver.config;

import com.nistruct.authorizationserver.model.CustomUser;
import com.nistruct.authorizationserver.model.KeyPairContainer;
import com.nistruct.authorizationserver.service.JwkService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.util.*;

@Component
@ConfigurationProperties(prefix = "config.oauth2")
public class CustomTokenEnhancer extends JwtAccessTokenConverter {

    private List<String> privateKey;
    private List<String> publicKey;

    private JsonParser objectMapper = JsonParserFactory.create();

    private RsaSigner signer;

    private String role;

    private String kid;

    @Autowired
    private JwkService jwkService;

    public List<String> getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(List<String> privateKey) {
        this.privateKey = privateKey;
    }

    public List<String> getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(List<String> publicKey) {
        this.publicKey = publicKey;
    }

    public CustomTokenEnhancer() {
        super();
    }


    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        CustomUser user = (CustomUser) authentication.getPrincipal();
        role = user.getAuthorities().stream()
                .filter(grantedAuthority -> grantedAuthority.getAuthority().contains("ROLE_"))
                .findFirst()
                .get()
                .getAuthority();

        Map<String, Object> info = new LinkedHashMap<>(accessToken.getAdditionalInformation());
        if (user.getId() != null)
            info.put("id", user.getId());
        if (user.getName() != null)
            info.put("name", user.getName());
        if (user.getUsername() != null)
            info.put("userName", user.getUsername());
        DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);
        customAccessToken.setAdditionalInformation(info);
        return super.enhance(customAccessToken, authentication);
    }

    @Override
    protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        String content;
        try {
            content = this.objectMapper.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
            Optional<KeyPairContainer> keyPairContainer = jwkService.getCachedKeyPairs().stream()
                    .filter(ckp -> ckp.getRole().equals(role)).findFirst();
            this.kid = keyPairContainer.get().getKeyId();
            this.signer = new RsaSigner((RSAPrivateKey) keyPairContainer.get().getKeyPair().getPrivate());
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot convert access token to JSON", ex);
        }
        Map<String, String> customHeaders = Collections.singletonMap("kid", this.kid);
        return JwtHelper.encode(content, this.signer, customHeaders)
                .getEncoded();
    }

}
