package fi.methics.musap.sdk.sscd.android;

import static fi.methics.musap.sdk.sscd.android.EthereumSigner.ethereumMessageHash;
import static fi.methics.musap.sdk.sscd.android.EthereumSigner.signMessage;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;


import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

import fi.methics.musap.sdk.api.MusapConstants;
import fi.methics.musap.sdk.attestation.AndroidKeyAttestation;
import fi.methics.musap.sdk.attestation.KeyAttestation;
import fi.methics.musap.sdk.extension.MusapSscdInterface;
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm;
import fi.methics.musap.sdk.internal.datatype.MusapKey;
import fi.methics.musap.sdk.internal.datatype.MusapLoA;
import fi.methics.musap.sdk.internal.datatype.MusapSignature;
import fi.methics.musap.sdk.internal.datatype.PublicKey;
import fi.methics.musap.sdk.internal.datatype.SignatureAlgorithm;
import fi.methics.musap.sdk.internal.datatype.SignatureFormat;
import fi.methics.musap.sdk.internal.datatype.SscdInfo;
import fi.methics.musap.sdk.internal.discovery.KeyBindReq;
import fi.methics.musap.sdk.internal.keygeneration.KeyGenReq;
import fi.methics.musap.sdk.internal.sign.SignatureReq;
import fi.methics.musap.sdk.internal.util.IdGenerator;
import fi.methics.musap.sdk.internal.util.MLog;
import fi.methics.musap.sdk.internal.util.StringUtil;

/**
 * MUSAP SSCD implementation for Android KeyStore
 * Note that this SSCD does not ask for authentication by default.
 * Authentication can be configure with step-up authentication policy.
 */
public class AndroidKeystoreSscd implements MusapSscdInterface<AndroidKeystoreSettings> {

    private Context context;

    private AndroidKeystoreSettings settings = new AndroidKeystoreSettings();

    public AndroidKeystoreSscd(Context context) {
        this.context = context;
    }

    public static final String SSCD_TYPE = "aks";

    @Override
    public MusapKey bindKey(KeyBindReq req) {
        // "Old" keys cannot be bound to MUSAP.
        // Use generateKey instead.
        throw new UnsupportedOperationException();
    }

    public EthereumSigner.Signature signSECp256k1(String message, String privateKeyHex){
        BigInteger privateKey = new BigInteger(privateKeyHex, 16);
        byte[] messageHash = ethereumMessageHash(message);

        return signMessage(messageHash, privateKey);
    }

    //THIS IS ONLY FOR secp256k1 to work
    private MusapKey createSECp256k1(KeyGenReq req, SscdInfo sscd) throws  Exception {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Retrieve SECP256K1 curve parameters
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

        // Create KeyPairGenerator for SECP256K1
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(ecSpec); // Initialize with SECP256K1 parameters

        KeyPair keyPair = kpg.generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        MLog.d("Key generation successful using SECP256K1");

        MusapKey generatedKey = new MusapKey.Builder()
                .setSscdType(MusapConstants.ANDROID_KS_TYPE)
                .setKeyAlias(req.getKeyAlias())
                .setSscdId(sscd.getSscdId())
                .setLoa(Arrays.asList(MusapLoA.EIDAS_SUBSTANTIAL, MusapLoA.ISO_LOA3))
                .setPublicKey(new PublicKey(keyPair))
                .setPrivateKeyHex(privateKeyToHex(privateKey))
                .setPublicKeyHex(publicKeyToHex(publicKey))
                .setKeyId(IdGenerator.generateKeyId())
                .setAlgorithm(req.getAlgorithm())
                .build();

        MLog.d("Generated key with KeyURI " + generatedKey.getKeyUri());

        return generatedKey;
    }


    // Convert private key to hex
    public static String privateKeyToHex(ECPrivateKey privateKey) {
        // The private key is a single scalar value (S)
        byte[] privateKeyBytes = privateKey.getS().toByteArray();
        return StringUtil.BytesToHexSEC256K1(privateKeyBytes);
    }

    // Convert public key to hex
    public static String publicKeyToHex(ECPublicKey publicKey) {
        // Get the public key point (x, y)
        ECPoint ecPoint = publicKey.getW();
        byte[] xBytes = ecPoint.getAffineX().toByteArray();
        byte[] yBytes = ecPoint.getAffineY().toByteArray();

        // Concatenate x and y with a prefix (0x04 for uncompressed point)
        byte[] publicKeyBytes = new byte[1 + xBytes.length + yBytes.length];
        publicKeyBytes[0] = 0x04; // Uncompressed format prefix
        System.arraycopy(xBytes, 0, publicKeyBytes, 1, xBytes.length);
        System.arraycopy(yBytes, 0, publicKeyBytes, 1 + xBytes.length, yBytes.length);

        return StringUtil.BytesToHexSEC256K1(publicKeyBytes);
    }



    @Override
    public MusapKey generateKey(KeyGenReq req) throws Exception {
        SscdInfo sscd = this.getSscdInfo();

        if (req.getAlgorithm().curve.equals("secp256k1")) {
            MLog.d("secp256k1 curve use different function");
            return this.createSECp256k1(req, sscd);
        }
        Security.removeProvider("BC");
        MLog.d("Remove provider");
        String                algorithm = this.resolveAlgorithm(req);
        AlgorithmParameterSpec algSspec = this.resolveAlgorithmParameterSpec(req);

        MLog.d("Generating with algorithm " + algorithm);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(req.getKeyAlias(),
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(
                        KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                        KeyProperties.SIGNATURE_PADDING_RSA_PSS);

        if (algSspec != null) {
            builder.setAlgorithmParameterSpec(algSspec);
            MLog.d("Algorithm spec " + algSspec);
        } else {
            MLog.d("No algoritm spec given");
        }

        KeyGenParameterSpec spec = builder.build();
        MLog.d("Algorithm spec " + spec);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, "AndroidKeyStore");
        kpg.initialize(spec);

        KeyPair keyPair = kpg.generateKeyPair();
        MLog.d("Key generation successful");

        MusapKey generatedKey = new MusapKey.Builder()
                .setSscdType(MusapConstants.ANDROID_KS_TYPE)
                .setKeyAlias(req.getKeyAlias())
                .setSscdId(sscd.getSscdId())
                .setLoa(Arrays.asList(MusapLoA.EIDAS_SUBSTANTIAL, MusapLoA.ISO_LOA3))
                .setPublicKey(new PublicKey(keyPair))
                .setKeyId(IdGenerator.generateKeyId())
                .setAlgorithm(req.getAlgorithm())
                .build();
        MLog.d("Generated key with KeyURI " + generatedKey.getKeyUri());

        return generatedKey;
    }

    @Override
    public MusapSignature sign(SignatureReq req) throws GeneralSecurityException, IOException {

        if (req.getAlgorithmString().equals("secp256k1")) {
            String data = req.getDataString();
            String privKey = req.getKey().getPrivateKeyHex().substring(2);

            MLog.d("secp256k1 signature use different function with data "+ data);
            EthereumSigner.Signature signature = this.signSECp256k1(data, privKey);
            return new MusapSignature(signature, req.getKey(), req.getAlgorithmString(), req.getFormat());
        }

        String alias = req.getKey().getKeyAlias();
        Security.removeProvider("BC");
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");

        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            MLog.d("Not an instance of a PrivateKeyEntry");
            return null;
        }

        SignatureAlgorithm algorithm = req.getAlgorithm();
        MLog.d("Signing " + new String(req.getData()) + " with algorithm " + algorithm);
        Signature s = Signature.getInstance(algorithm.getJavaAlgorithm());

        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();

        s.initSign(privateKey);
        s.update(req.getData());

        byte[] signature = s.sign();
        MLog.d("Signature byte len=" + signature.length);
        MLog.d("Signature hex=" + bytesToHex(signature));
        MLog.d("Signature=" + Base64.encodeToString(signature, Base64.DEFAULT));

        return new MusapSignature(signature, req.getKey(), algorithm, req.getFormat());
    }

    @Override
    public SscdInfo getSscdInfo() {
        return new SscdInfo.Builder()
                .setSscdName("Android KeyStore")
                .setSscdType(SSCD_TYPE)
                .setCountry("FI")
                .setProvider("Google")
                .setKeygenSupported(true)
                .setSupportedAlgorithms(Arrays.asList(
                        KeyAlgorithm.RSA_2K,
                        KeyAlgorithm.ECC_P256_R1,
                        KeyAlgorithm.ECC_P256_K1,
                        KeyAlgorithm.ECC_P384_K1))
                .setSupportedFormats(Arrays.asList(SignatureFormat.RAW))
                .build();
    }

    @Override
    public AndroidKeystoreSettings getSettings() {
        return settings;
    }

    @Override
    public KeyAttestation getKeyAttestation() {
        return new AndroidKeyAttestation();
    }

    /**
     * Resolve the {@link AlgorithmParameterSpec} to use with key generation
     * @param req Key generation request
     * @return AlgorithmParameterSpec
     */
    private AlgorithmParameterSpec resolveAlgorithmParameterSpec(KeyGenReq req) {
        KeyAlgorithm algorithm = req.getAlgorithm();
        if (algorithm == null) {
            MLog.d("Null algorithm");
            return null;
        }
        if (algorithm.isRsa()) {
            MLog.d("RSA algorithm");
            return new RSAKeyGenParameterSpec(algorithm.bits, RSAKeyGenParameterSpec.F4);
        } else {
            MLog.d("ECC algorithm");
            return new ECGenParameterSpec(algorithm.curve);
        }
    }

    /**
     * Resolve the key algorithm (EC or RSA)
     * @param req Key generation request
     * @return "EC" or "RSA" (default EC)
     */
    private String resolveAlgorithm(KeyGenReq req) {

        KeyAlgorithm algorithm = req.getAlgorithm();
        if (algorithm == null) return KeyProperties.KEY_ALGORITHM_EC;
        if (algorithm.isRsa()) {
            return KeyProperties.KEY_ALGORITHM_RSA;
        } else {
            return KeyProperties.KEY_ALGORITHM_EC;
        }
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

}
