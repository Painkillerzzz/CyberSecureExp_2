package edu.cybersecure.exp2;

import java.io.Serializable;

/**
 * 协议交互使用的报文类型定义。
 *
 * 为简单起见，所有报文均只包含必要的字段，以字节数组形式承载密文。
 */
public final class Messages {

    private Messages() {
    }

    public static class Msg1 implements Serializable {
        private static final long serialVersionUID = 1L;
        public final String identityA;
        public final byte[] encPkAByPw; // E0(pw, pkA)

        public Msg1(String identityA, byte[] encPkAByPw) {
            this.identityA = identityA;
            this.encPkAByPw = encPkAByPw;
        }
    }

    public static class Msg2 implements Serializable {
        private static final long serialVersionUID = 1L;
        public final byte[] encKsByPwAndPkA; // E0(pw, E(pkA, Ks))

        public Msg2(byte[] encKsByPwAndPkA) {
            this.encKsByPwAndPkA = encKsByPwAndPkA;
        }
    }

    public static class Msg3 implements Serializable {
        private static final long serialVersionUID = 1L;
        public final byte[] encNaByKs; // E1(Ks, Na)

        public Msg3(byte[] encNaByKs) {
            this.encNaByKs = encNaByKs;
        }
    }

    public static class Msg4 implements Serializable {
        private static final long serialVersionUID = 1L;
        public final byte[] encNaNbByKs; // E1(Ks, Na || Nb)

        public Msg4(byte[] encNaNbByKs) {
            this.encNaNbByKs = encNaNbByKs;
        }
    }

    public static class Msg5 implements Serializable {
        private static final long serialVersionUID = 1L;
        public final byte[] encNbByKs; // E1(Ks, Nb)

        public Msg5(byte[] encNbByKs) {
            this.encNbByKs = encNbByKs;
        }
    }
}

