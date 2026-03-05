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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * 实体 B 的进程，通过 Socket 监听端口，与 A 运行 Bellovin-Merritt 协议。
 *
 * 启动参数：
 *   java -cp target/CyberSecureExp_2-1.0-SNAPSHOT.jar edu.cybersecure.exp2.Bob <port> <password>
 */
public class Bob {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("用法: java ... Bob <port> <password>");
            return;
        }
        int port = Integer.parseInt(args[0]);
        String password = args[1];

        SecretKeySpec pwAesKey = CryptoUtils.deriveAesKeyFromPassword(password);

        System.out.println("[B] 使用口令派生 AES 密钥完成初始化");

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("[B] 等待来自 A 的连接，端口: " + port);
            try (Socket socket = serverSocket.accept()) {
                System.out.println("[B] 已接受连接，来自: " + socket.getRemoteSocketAddress());
                try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
                     ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

                    // Step 1: 接收 A 的身份与 pkA 密文
                    Msg1 m1;
                    try {
                        m1 = (Msg1) ois.readObject();
                    } catch (Exception e) {
                        System.out.println("[B] 接收来自 A 的首个报文失败，认证终止。");
                        return;
                    }
                    System.out.println("[B] 收到来自 A 的身份标识: " + m1.identityA);

                    byte[] pkABytes;
                    try {
                        pkABytes = CryptoUtils.aesDecrypt(m1.encPkAByPw, pwAesKey);
                    } catch (Exception e) {
                        System.out.println("[B] 使用口令解密 pk_A 失败，可能口令不一致或报文被篡改，认证终止。");
                        return;
                    }
                    PublicKey pkA;
                    try {
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        pkA = keyFactory.generatePublic(new X509EncodedKeySpec(pkABytes));
                    } catch (Exception e) {
                        System.out.println("[B] pk_A 格式非法，认证终止。");
                        return;
                    }
                    System.out.println("[B] 已使用口令成功解密得到 pk_A");

                    // Step 2: 生成会话密钥 Ks，并发送两重加密后的 E0(pw, E(pkA, Ks))
                    byte[] Ks = CryptoUtils.randomBytes(16); // 128-bit 会话密钥
                    byte[] encKsByPkA;
                    try {
                        javax.crypto.Cipher rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        rsaCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pkA);
                        encKsByPkA = rsaCipher.doFinal(Ks);
                    } catch (Exception e) {
                        System.out.println("[B] 使用 pk_A 加密会话密钥失败，认证终止。");
                        return;
                    }

                    byte[] encKsByPwAndPkA;
                    try {
                        encKsByPwAndPkA = CryptoUtils.aesEncrypt(encKsByPkA, pwAesKey);
                    } catch (Exception e) {
                        System.out.println("[B] 使用口令对会话密钥密文加密失败，认证终止。");
                        return;
                    }
                    oos.writeObject(new Msg2(encKsByPwAndPkA));
                    oos.flush();
                    System.out.println("[B] 已发送 Msg2：E0(pw, E(pkA, Ks))");

                    // Step 3: 接收 E1(Ks, Na)
                    SecretKey desKey = CryptoUtils.deriveDesKeyFromSessionKey(Ks);
                    Msg3 m3;
                    try {
                        m3 = (Msg3) ois.readObject();
                    } catch (Exception e) {
                        System.out.println("[B] 接收包含 Na 的报文失败，认证终止。");
                        return;
                    }
                    byte[] Na;
                    try {
                        Na = CryptoUtils.desDecrypt(m3.encNaByKs, desKey);
                    } catch (Exception e) {
                        System.out.println("[B] 使用 Ks 解密 Na 失败，可能会话密钥不一致或报文被篡改，认证终止。");
                        return;
                    }
                    System.out.println("[B] 已解密得到随机数 Na");

                    // Step 4: 生成 Nb，发送 E1(Ks, Na || Nb)
                    byte[] Nb = CryptoUtils.randomBytes(Na.length);
                    byte[] NaNb = new byte[Na.length + Nb.length];
                    System.arraycopy(Na, 0, NaNb, 0, Na.length);
                    System.arraycopy(Nb, 0, NaNb, Na.length, Nb.length);

                    byte[] encNaNb;
                    try {
                        encNaNb = CryptoUtils.desEncrypt(NaNb, desKey);
                    } catch (Exception e) {
                        System.out.println("[B] 使用 Ks 加密 Na||Nb 失败，认证终止。");
                        return;
                    }
                    oos.writeObject(new Msg4(encNaNb));
                    oos.flush();
                    System.out.println("[B] 已发送 Msg4：E1(Ks, Na||Nb)");

                    // Step 5: 接收 E1(Ks, Nb)，完成对 A 的验证
                    Msg5 m5;
                    try {
                        m5 = (Msg5) ois.readObject();
                    } catch (Exception e) {
                        System.out.println("[B] 接收包含 Nb 的报文失败，认证终止。");
                        return;
                    }
                    byte[] NbFromA;
                    try {
                        NbFromA = CryptoUtils.desDecrypt(m5.encNbByKs, desKey);
                    } catch (Exception e) {
                        System.out.println("[B] 使用 Ks 解密 Nb 失败，认证终止。");
                        return;
                    }

                    if (Arrays.equals(NbFromA, Nb)) {
                        System.out.println("[B] 验证 Nb 成功，确认对方为 A。双向认证完成！");
                        System.out.println("[B] 共享会话密钥 Ks 可用于后续对称加密通信。");
                    } else {
                        System.out.println("[B] 验证 Nb 失败，认证终止。");
                    }
                }
            }
        }
    }
}

