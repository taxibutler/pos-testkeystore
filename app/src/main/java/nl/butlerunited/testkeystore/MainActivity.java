package nl.butlerunited.testkeystore;

import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "TestKeyStore";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        try {
            testKeystore();

        } catch (KeyStoreException | NoSuchAlgorithmException | NoSuchProviderException |
                 InvalidAlgorithmParameterException | UnrecoverableKeyException |
                 NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | CertificateException | IOException e) {
            e.printStackTrace();
        }
    }

    private void testKeystore() throws KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, CertificateException, IOException {
        // 1. Get the Android keystore
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Log.d(TAG, "1. Get the Android keystore");

        // 2. Generate and store the key pair
        if (!keyStore.containsAlias("my_key")) {
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 1);
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(getApplicationContext())
                    .setAlias("my_key")
                    .setSubject(new javax.security.auth.x500.X500Principal("CN=my_key"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            generator.initialize(spec);
            KeyPair keyPair = generator.generateKeyPair();
        }
        Log.d(TAG, "2. Generate and store the key pair");

        // 3. Get the public and private keys
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("my_key", null);
        PublicKey publicKey = keyStore.getCertificate("my_key").getPublicKey();
        Log.d(TAG, "3. Get the public and private keys");

        // 4. Use the public key to encrypt data
        String plainText = "Hello World";
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        Log.d(TAG, "4. Use the public key to encrypt data: " + plainText);

        // 5. Use the private key to decrypt data
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decryptedText = new String(decryptedBytes);
        Log.d(TAG, "5. Use the private key to decrypt data");

        // Output the decrypted plaintext
        Log.d(TAG, "6. Output the decrypted plaintextDecrypted Text: " + decryptedText);
        Toast.makeText(this, decryptedText, Toast.LENGTH_LONG).show();
    }
}