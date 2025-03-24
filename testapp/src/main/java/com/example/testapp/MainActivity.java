package com.example.testapp;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import androidx.appcompat.app.AppCompatActivity;

import java.util.List;

import fi.methics.musap.sdk.api.MusapCallback;
import fi.methics.musap.sdk.api.MusapClient;
import fi.methics.musap.sdk.api.MusapException;
import fi.methics.musap.sdk.internal.datatype.KeyAlgorithm;
import fi.methics.musap.sdk.internal.datatype.MusapKey;
import fi.methics.musap.sdk.internal.datatype.MusapSignature;
import fi.methics.musap.sdk.internal.datatype.SignatureAlgorithm;
import fi.methics.musap.sdk.internal.keygeneration.KeyGenReq;
import fi.methics.musap.sdk.internal.sign.SignatureReq;
import fi.methics.musap.sdk.internal.util.MLog;
import fi.methics.musap.sdk.internal.util.MusapSscd;
import fi.methics.musap.sdk.sscd.android.AndroidKeystoreSscd;
import fi.methics.musap.sdk.sscd.android.EthereumSigner;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        System.out.println("Hello, World!");

        MusapClient.init(this);
        MusapClient.enableSscd(new AndroidKeystoreSscd(this), "1");

        Button generateKeyButton = findViewById(R.id.generateKeyButton);
        Button signDataButton = findViewById(R.id.signDataButton);
        Button sharedSecretButton = findViewById(R.id.sharedSecretButton);


        String keyId = "8fcf8b50-f492-4368-90a5-8067e1f9752d";
        generateKeyButton.setOnClickListener(v -> generateKey("1234", MainActivity.this));
        signDataButton.setOnClickListener(v -> signData(keyId));
        sharedSecretButton.setOnClickListener(v -> generateSharedSecret(keyId));

    }

    public void signData(String keyId) {
        try {
            MusapKey key = MusapClient.getKeyByKeyID(keyId);

            String data = "hello";
            SignatureReq req = new SignatureReq.Builder(SignatureAlgorithm.SIGNATURE_SECP256K1)
                    .setKey(key)
                    .setData(data).createSignatureReq();


            MusapClient.sign(req, new MusapCallback<MusapSignature>() {
                @Override
                public void onSuccess(MusapSignature mSig) {

                    EthereumSigner.Signature signature = mSig.getEthSignature();

                    System.out.println("r: 0x" + signature.r.toString(16));
                    System.out.println("s: 0x" + signature.s.toString(16));
                    System.out.println("v: " + signature.v);

                    MLog.d("Signature successful: ");
                }

                @Override
                public void onException(MusapException e) {
                    MLog.e("Failed to sign", e.getCause());
                }
            });
        } catch (Exception e) {
            System.out.println("SIGN_ERROR: " + e.getMessage());
        }
    }

    public void generateSharedSecret(String keyId) {
        try {

            String privateKeyHex = "8e9b2cab68eac300275338af03662f2f3f40913037d65ccabc1214ef6a765a8a";
            String publicKeyHex = "041daed29134b538f4cdaaedc62090f6cd346a4350bae6933815ca89834a71ca411cbca2a0f705c090b1399c2908f63b55bc2caaf0eec8564cc0d993e8dd8090f0";

            String a = MusapClient.computeECDHSharedSecret(privateKeyHex, publicKeyHex);

            System.out.println("correct 132b03e4af69cc639b3c9c5aadb8dc5c7c4921970cd3a0d3bba9bd0411bcfa49::answer::" + a);
            System.out.println("132b03e4af69cc639b3c9c5aadb8dc5c7c4921970cd3a0d3bba9bd0411bcfa49".equals(a));

            MusapKey kee = MusapClient.getKeyByKeyID(keyId);
            String a1 = MusapClient.computeECDHSharedSecretByKey(kee, publicKeyHex);
            System.out.println("key ::" + a1);
        } catch (Exception e) {
            System.out.println("ECDH_ERROR: " + e.getMessage());
        }
    }


    public void generateKey(String keyAlias, Activity activity) {
        try {

            View currentView = activity.getWindow().getDecorView();

            KeyGenReq req = new KeyGenReq.Builder()
                    .setActivity(activity)
                    .setView(currentView)
                    .setKeyAlias(keyAlias)
                    .setKeyAlgorithm(KeyAlgorithm.ECC_P256_K1)
                    .createKeyGenReq();

            List<MusapSscd> enabledSscds = MusapClient.listEnabledSscds();
            if (enabledSscds.isEmpty()) {
                System.out.println("NO_ENABLED_SSCD No enabled SSCDs found.");
                return;
            }

            MusapClient.generateKey(enabledSscds.get(0), req, new MusapCallback<MusapKey>() {
                @Override
                public void onSuccess(MusapKey result) {

                    System.out.println("teeeest Successfully generated key: " + result.getKeyAlias());
                    System.out.println("teeeest Successfully getPrivateKeyHex key: " + result.getPrivateKeyHex());
                    System.out.println("teeeest Successfully getPublicKeyHex key: " + result.getPublicKeyHex());
                }

                @Override
                public void onException(MusapException e) {
                    System.out.println("KEY_GEN_ERROR" + e);
                }
            });

        } catch (Exception e) {
            System.out.println("GENERATE_ERROR" + e);
        }
    }


}
