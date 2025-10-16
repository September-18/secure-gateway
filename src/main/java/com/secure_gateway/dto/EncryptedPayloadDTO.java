package com.secure_gateway.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EncryptedPayloadDTO {
    private String cipherText;
    private String publicKey;
    private String nonce;
}