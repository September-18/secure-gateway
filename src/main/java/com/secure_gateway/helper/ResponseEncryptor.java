package com.secure_gateway.helper;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.secure_gateway.dto.EncryptedPayloadDTO;
import com.secure_gateway.util.CrytoUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static com.m2e.gateway.constant.CryptographyConstant.*;

@Component
@Slf4j
@AllArgsConstructor
public class ResponseEncryptor {
    private final ObjectMapper objectMapper = new ObjectMapper();

    public Flux<DataBuffer> encryptResponse(Flux<? extends DataBuffer> fluxBody, ServerWebExchange exchange, DataBufferFactory bufferFactory) {
        return fluxBody.flatMap(dataBuffer -> {
            byte[] content = new byte[dataBuffer.readableByteCount()];
            dataBuffer.read(content);
            DataBufferUtils.release(dataBuffer);

            try {
                String originalResponse = new String(content, StandardCharsets.UTF_8);
                String userPublicKeyBase64 = exchange.getAttribute(USER_PUBLIC_KEY_BASE64);

                if (!StringUtils.hasText(userPublicKeyBase64)) {
                    throw new IllegalStateException("Missing public key in context");
                }

                EncryptedPayloadDTO encryptedPayload = CrytoUtil.encrypt(
                        originalResponse,
                        Base64.getDecoder().decode(userPublicKeyBase64),
                        Base64.getDecoder().decode(exchange.getAttributes().get(SECRET_KEY).toString()),
                        Base64.getDecoder().decode(exchange.getAttributes().get(PUBLIC_KEY).toString()));

                String responseJson = objectMapper.writeValueAsString(encryptedPayload);
                log.info("Encrypted response payload: {}",responseJson);

                byte[] responseBytes = responseJson.getBytes(StandardCharsets.UTF_8);
                return Mono.just(bufferFactory.wrap(responseBytes));

            } catch (Exception e) {
                log.error("Response encryption failed", e);
                return Mono.error(new RuntimeException("Response encryption failed", e));
            }
        });
    }
}