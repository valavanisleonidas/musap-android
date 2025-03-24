package fi.methics.musap.sdk.sscd.android;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.*;

import javax.crypto.KeyAgreement;

public class EcdhKeyCalculator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String computeSharedSecret(String privateKeyHex, String publicKeyHex) throws Exception {
        ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");

        // Build private key
        BigInteger d = new BigInteger(privateKeyHex, 16);
        PrivateKey privateKey = keyFactory.generatePrivate(new ECPrivateKeySpec(d, ecSpec));

        // Build public key from uncompressed point
        BigInteger x = new BigInteger(publicKeyHex.substring(2, 66), 16);
        BigInteger y = new BigInteger(publicKeyHex.substring(66), 16);
        ECPoint pubPoint = ecSpec.getCurve().createPoint(x, y);
        PublicKey publicKey = keyFactory.generatePublic(new ECPublicKeySpec(pubPoint, ecSpec));

        // ECDH key agreement
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return bytesToHex(keyAgreement.generateSecret());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
