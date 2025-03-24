package fi.methics.musap.sdk.sscd.android;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;

public class EthereumSigner {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final ECDomainParameters CURVE;

    static {
        SecP256K1Curve curve = new SecP256K1Curve();
        ECPoint G = curve.decodePoint(Hex.decode("04"
                + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
        BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        CURVE = new ECDomainParameters(curve, G, N, BigInteger.ONE);
    }

    public static byte[] ethereumMessageHash(String message) {
        String prefix = "\u0019Ethereum Signed Message:\n" + message.length();
        byte[] prefixed = (prefix + message).getBytes(StandardCharsets.UTF_8);
        return keccak256(prefixed);
    }


    public static Signature signMessage(byte[] hash, BigInteger privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new KeccakDigest(256)));
        ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(privateKey, CURVE);
        signer.init(true, privKeyParams);
        BigInteger[] components = signer.generateSignature(hash);

        BigInteger r = components[0];
        BigInteger s = components[1];
        BigInteger n = CURVE.getN();

        // Enforce low-S value (Ethereum requirement)
        if (s.compareTo(n.shiftRight(1)) > 0) {
            s = n.subtract(s);
        }

        // Recover the public key to calculate `v`
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            ECPoint q = recoverFromSignature(i, r, s, hash);
            if (q != null) {
                BigInteger k = q.normalize().getXCoord().toBigInteger();
                BigInteger expected = publicKeyFromPrivate(privateKey).normalize().getXCoord().toBigInteger();
                if (k.equals(expected)) {
                    recId = i;
                    break;
                }
            }
        }

        int v = recId + 27;
        return new Signature(r, s, v);
    }

    public static ECPoint publicKeyFromPrivate(BigInteger privKey) {
        return CURVE.getG().multiply(privKey);
    }

    public static byte[] keccak256(byte[] input) {
        KeccakDigest digest = new KeccakDigest(256);
        digest.update(input, 0, input.length);
        byte[] hash = new byte[32];
        digest.doFinal(hash, 0);
        return hash;
    }

    public static ECPoint recoverFromSignature(int recId, BigInteger r, BigInteger s, byte[] hash) {
        BigInteger n = CURVE.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));

        SecP256K1Curve curve = (SecP256K1Curve) CURVE.getCurve();
        if (x.compareTo(curve.getField().getCharacteristic()) >= 0) return null;

        ECPoint R = decompressKey(x, (recId & 1) == 1);
        if (!R.multiply(n).isInfinity()) return null;

        BigInteger e = new BigInteger(1, hash);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = s.multiply(rInv).mod(n);
        BigInteger eNeg = n.subtract(e).multiply(rInv).mod(n);

        ECPoint Q = CURVE.getG().multiply(eNeg).add(R.multiply(srInv));
        return Q;
    }

    public static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        ECCurve curve = CURVE.getCurve();
        ECFieldElement x = curve.fromBigInteger(xBN);
        ECFieldElement alpha = x.multiply(x.square().add(curve.getA())).add(curve.getB());
        ECFieldElement beta = alpha.sqrt();
        if (beta == null) return null;

        BigInteger betaBI = beta.toBigInteger();
        if (betaBI.testBit(0) != yBit) {
            beta = beta.negate();
        }

        return curve.createPoint(xBN, beta.toBigInteger());
    }

    public static class Signature {
        public final BigInteger r;
        public final BigInteger s;
        public final int v;

        public Signature(BigInteger r, BigInteger s, int v) {
            this.r = r;
            this.s = s;
            this.v = v;
        }
    }
}