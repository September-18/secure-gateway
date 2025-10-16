package com.secure_gateway.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.iwebpp.crypto.TweetNaclFast;
import com.iwebpp.crypto.TweetNaclFast.Box.KeyPair;
import com.m2e.gateway.repository.SecretkeyGeneratorRepository;
import com.m2e.model.sso.base.SecretkeyGenerator;
import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.m2e.gateway.constant.CryptographyConstant.*;

@Configuration
@AllArgsConstructor
public class CryptographyConfig {
    private final SecretkeyGeneratorRepository secretkeyGeneratorRepository;

    @Bean("secretKeyMap")
    public Map<String, String> generateSecretKey() {
        Map<String, String> map = new HashMap<>();

        KeyPair beKeypair = TweetNaclFast.Box.keyPair();
        String publicKey = Base64.getEncoder().encodeToString(beKeypair.getPublicKey());
        String secretKey = Base64.getEncoder().encodeToString(beKeypair.getSecretKey());

        SecretkeyGenerator secretkeyGenerator = new SecretkeyGenerator();
        secretkeyGenerator.setId(UUID.randomUUID().toString());
        secretkeyGenerator.setPublicKey(publicKey);
        secretkeyGenerator.setSecretKey(secretKey);
        secretkeyGenerator.setCreatedDate(OffsetDateTime.now());

        secretkeyGeneratorRepository.save(secretkeyGenerator);

        map.put(ID, secretkeyGenerator.getId());
        map.put(PUBLIC_KEY, secretkeyGenerator.getPublicKey());
        map.put(SECRET_KEY, secretkeyGenerator.getSecretKey());

        return map;
    }

    @Bean("gatewayObjectMapper")
    public ObjectMapper objectMapper(){
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        return objectMapper;
    }
}