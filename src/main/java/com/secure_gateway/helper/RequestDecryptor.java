package com.secure_gateway.helper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure_gateway.dto.EncryptedPayloadDTO;
import com.secure_gateway.util.CrytoUtil;
import jakarta.annotation.PostConstruct;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.m2e.gateway.constant.CryptographyConstant.SECRET_KEY;
import static com.m2e.gateway.constant.CryptographyConstant.USER_PUBLIC_KEY_BASE64;

@Component
@Slf4j
public class RequestDecryptor {
    @Autowired
    @Qualifier("gatewayObjectMapper")
    private ObjectMapper objectMapper;

    public String decryptRequest(byte[] requestBodyBytes, ServerWebExchange exchange) throws Exception {
        String requestBody = new String(requestBodyBytes, StandardCharsets.UTF_8);
        EncryptedPayloadDTO encryptedPayload = objectMapper.readValue(requestBody, EncryptedPayloadDTO.class);

        if (encryptedPayload.getCipherText() == null) {
            return null;
        }

        log.debug("Encrypted request payload: {}",objectMapper.writeValueAsString(encryptedPayload));
        validateRequestBody(encryptedPayload);

        String decryptedPayload = CrytoUtil.decrypt(
                Base64.getDecoder().decode(encryptedPayload.getCipherText()),
                Base64.getDecoder().decode(encryptedPayload.getNonce()),
                Base64.getDecoder().decode(encryptedPayload.getPublicKey()),
                Base64.getDecoder().decode(exchange.getAttributes().get(SECRET_KEY).toString()));

        log.debug("Decrypted request payload: {}", decryptedPayload);

        exchange.getAttributes().put(USER_PUBLIC_KEY_BASE64, encryptedPayload.getPublicKey());
        return decryptedPayload;
    }

    @SneakyThrows
    private void validateRequestBody(EncryptedPayloadDTO payload) {
        boolean hasCipherText = StringUtils.hasText(payload.getCipherText());
        boolean hasNonce = StringUtils.hasText(payload.getNonce());
        boolean hasPublicKey = StringUtils.hasText(payload.getPublicKey());

        if (!hasCipherText || !hasNonce || !hasPublicKey) {
            log.error("Invalid request body: Missing required fields! cipherText: {}, nonce: {}, publicKey: {}",hasCipherText, hasNonce, hasPublicKey);
            throw new IllegalArgumentException("Invalid request body: Missing required fields");
        }
    }

    @PostConstruct
    public void postConstruct() {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }
}