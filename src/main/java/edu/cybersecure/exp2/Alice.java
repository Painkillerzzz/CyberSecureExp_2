package edu.cybersecure.exp2;

import edu.cybersecure.exp2.Messages.Msg1;
import edu.cybersecure.exp2.Messages.Msg2;
import edu.cybersecure.exp2.Messages.Msg3;
import edu.cybersecure.exp2.Messages.Msg4;
import edu.cybersecure.exp2.Messages.Msg5;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * 实体 A 的进程，主动连接 B，完成 Bellovin-Merritt 协议的全部步骤。
 *
 * 启动参数：
 *   java -cp target/CyberSecureExp_2-1.0-SNAPSHOT.jar edu.cybersecure.exp2.Alice <host> <port> <password>
 */
public class Alice {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("用法: java ... Alice <host> <port> <password>");
            return;
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String password = args[2];

        SecretKeySpec pwAesKey = CryptoUtils.deriveAesKeyFromPassword(password);

        System.out.println("[A] 使用口令派生 AES 密钥完成初始化");

        // Step 1: 生成一次性 RSA 密钥对 (pkA, skA)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey pkA = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey skA = (RSAPrivateKey) keyPair.getPrivate();

        byte[] pkABytes = pkA.getEncoded();
        byte[] encPkAByPw = CryptoUtils.aesEncrypt(pkABytes, pwAesKey);

        System.out.println("[A] 已生成临时 RSA 公私钥对，并用口令加密 pk_A");

        // 与 B 建立连接
        try (Socket socket = new Socket(host, port)) {
            System.out.println("[A] 已连接到 B: " + host + ":" + port);
            try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

                // 发送 Msg1：身份 + E0(pw, pkA)
                Msg1 m1 = new Msg1("Alice", encPkAByPw);
                oos.writeObject(m1);
                oos.flush();
                System.out.println("[A] 已发送 Msg1：身份和加密后的 pk_A");

                // Step 2: 接收 Msg2：E0(pw, E(pkA, Ks))，解密得到 Ks
                Msg2 m2;
                try {
                    m2 = (Msg2) ois.readObject();
                } catch (Exception e) {
                    System.out.println("[A] 未能收到包含会话密钥的响应，认证终止。");
                    return;
                }

                byte[] encKsByPkA;
                try {
                    encKsByPkA = CryptoUtils.aesDecrypt(m2.encKsByPwAndPkA, pwAesKey);
                } catch (Exception e) {
                    System.out.println("[A] 使用口令解密会话密钥失败，可能口令不一致或报文被篡改，认证终止。");
                    return;
                }

                byte[] Ks;
                try {
                    javax.crypto.Cipher rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipher.init(javax.crypto.Cipher.DECRYPT_MODE, skA);
                    Ks = rsaCipher.doFinal(encKsByPkA);
                } catch (Exception e) {
                    System.out.println("[A] 使用私钥解密会话密钥失败，认证终止。");
                    return;
                }
                System.out.println("[A] 已成功解密得到会话密钥 Ks");

                // Step 3: 生成随机数 Na，发送 E1(Ks, Na)
                byte[] Na = CryptoUtils.randomBytes(16);
                SecretKey desKey = CryptoUtils.deriveDesKeyFromSessionKey(Ks);
                byte[] encNa;
                try {
                    encNa = CryptoUtils.desEncrypt(Na, desKey);
                } catch (Exception e) {
                    System.out.println("[A] 使用 Ks 加密 Na 失败，认证终止。");
                    return;
                }
                oos.writeObject(new Msg3(encNa));
                oos.flush();
                System.out.println("[A] 已发送 Msg3：E1(Ks, Na)");

                // Step 4: 接收 E1(Ks, Na || Nb)，验证 Na，并得到 Nb
                Msg4 m4;
                try {
                    m4 = (Msg4) ois.readObject();
                } catch (Exception e) {
                    System.out.println("[A] 未能收到包含 Na||Nb 的响应，认证终止。");
                    return;
                }
                byte[] NaNb;
                try {
                    NaNb = CryptoUtils.desDecrypt(m4.encNaNbByKs, desKey);
                } catch (Exception e) {
                    System.out.println("[A] 使用 Ks 解密 Na||Nb 失败，可能会话密钥不一致或报文被篡改，认证终止。");
                    return;
                }
                if (NaNb.length % 2 != 0) {
                    System.out.println("[A] 收到的 Na||Nb 长度异常，认证终止。");
                    return;
                }
                int half = NaNb.length / 2;
                byte[] NaFromB = Arrays.copyOfRange(NaNb, 0, half);
                byte[] Nb = Arrays.copyOfRange(NaNb, half, NaNb.length);

                if (!Arrays.equals(NaFromB, Na)) {
                    System.out.println("[A] 验证 Na 失败，认证终止。");
                    return;
                }
                System.out.println("[A] 验证 Na 成功，确认对方持有 Ks。");

                // Step 5: 发送 E1(Ks, Nb)
                byte[] encNb;
                try {
                    encNb = CryptoUtils.desEncrypt(Nb, desKey);
                } catch (Exception e) {
                    System.out.println("[A] 使用 Ks 加密 Nb 失败，认证终止。");
                    return;
                }
                oos.writeObject(new Msg5(encNb));
                oos.flush();
                System.out.println("[A] 已发送 Msg5：E1(Ks, Nb)");
                System.out.println("[A] 双向认证完成，A 与 B 已共享会话密钥 Ks，可用于后续对称加密通信。");
            }
        }
    }
}

