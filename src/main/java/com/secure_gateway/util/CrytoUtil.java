package com.secure_gateway.util;

import com.iwebpp.crypto.TweetNaclFast;
import com.secure_gateway.dto.EncryptedPayloadDTO;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
public class CrytoUtil {
    public static String decrypt(byte[] cipherText, byte[] nonce, byte[] theirPublicKey, byte[] mySecretKey) {
        TweetNaclFast.Box box = new TweetNaclFast.Box(theirPublicKey, mySecretKey);
        byte[] decryptedText = box.open(cipherText, nonce);

        if (decryptedText == null) {
            log.error("Decryption failed: invalid ciphertext or nonce or key");
            throw new IllegalArgumentException("Decryption failed: invalid ciphertext or nonce or key");
        }

        return new String(decryptedText, StandardCharsets.UTF_8);
    }

    public static EncryptedPayloadDTO encrypt(String plainText, byte[] theirPublicKey, byte[] mySecretKey, byte[] myPublicKey) {
        TweetNaclFast.Box box = new TweetNaclFast.Box(theirPublicKey, mySecretKey);
        byte[] nonce = TweetNaclFast.randombytes(box.nonceLength);
        byte[] encryptedText = box.box(plainText.getBytes(StandardCharsets.UTF_8), nonce);

        return EncryptedPayloadDTO.builder().cipherText(Base64.getEncoder().encodeToString(encryptedText))
                .nonce(Base64.getEncoder().encodeToString(nonce))
                .publicKey(Base64.getEncoder().encodeToString(myPublicKey))
                .build();
    }
}
