package edu.cybersecure.exp2;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * 协议中使用到的基础密码学工具。
 * 使用：
 *  - E0：AES/ECB/PKCS5Padding，密钥由口令派生；
 *  - E1：DES/ECB/PKCS5Padding，密钥为会话密钥 Ks 截断。
 */
public final class CryptoUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoUtils() {
    }

    public static byte[] randomBytes(int length) {
        byte[] b = new byte[length];
        RANDOM.nextBytes(b);
        return b;
    }

    /**
     * 先对口令做 Base64 编码，再计算 SHA-256 散列，然后截断/填充为 AES 密钥。
     */
    public static SecretKeySpec deriveAesKeyFromPassword(String password) throws Exception {
        byte[] pwBytes = password.getBytes(StandardCharsets.UTF_8);
        String base64 = Base64.getEncoder().encodeToString(pwBytes);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(base64.getBytes(StandardCharsets.UTF_8));
        byte[] keyBytes = Arrays.copyOf(hash, 16); // AES-128
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 会话密钥 Ks 生成 DES 密钥：取前 8 字节作为 DES key。
     */
    public static SecretKey deriveDesKeyFromSessionKey(byte[] sessionKey) throws Exception {
        byte[] keyBytes = Arrays.copyOf(sessionKey, 8);
        DESKeySpec desKeySpec = new DESKeySpec(keyBytes);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        return factory.generateSecret(desKeySpec);
    }

    public static byte[] aesEncrypt(byte[] plaintext, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public static byte[] aesDecrypt(byte[] ciphertext, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static byte[] desEncrypt(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public static byte[] desDecrypt(byte[] ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }
}

