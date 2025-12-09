package encrypt;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.*;
import java.io.*;

import javax.crypto.*;
import java.io.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class ConfigFileEncryptor {

    public static void main(String[] args) throws Exception {
        String inputFile = "test.txt";
        String keystoreFile = "test.jks";
        String configFile = "";
        String keystorePassword = "";

        SecretKey fileKey = generateAESKey();
        encryptFile(inputFile, fileKey);
        saveKeyToKeystore(keystoreFile, keystorePassword, fileKey);
        Properties config = new Properties();
        encryptAndStorePassword(keystorePassword, config);

        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            config.store(fos, "Encrypted keystore password configuration");
        }
    }

    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private static void encryptFile(String inputFile, SecretKey key)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] iv = cipher.getIV();

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(inputFile + ".enc")) {
            fos.write(iv);
            byte[] buffer = new byte[4096];
            int bytesRead;

            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                }
            }
        }
    }

    private static void saveKeyToKeystore(String keystoreFile, String password,
                                          SecretKey key) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        ks.load(null, null);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter entryPassword =
                new KeyStore.PasswordProtection(password.toCharArray());

        ks.setEntry("fileEncryptionKey", secretKeyEntry, entryPassword);
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }
    }

    private static void encryptAndStorePassword(String password, Properties config)
            throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];
        random.nextBytes(salt);
        random.nextBytes(iv);

        int iterations = 65536;
        int keyLength = 256;

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));

        byte[] encryptedPassword = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));

        Base64.Encoder encoder = Base64.getEncoder();

        config.setProperty("keystore.password.enc",
                encoder.encodeToString(encryptedPassword));
        config.setProperty("keystore.password.salt",
                encoder.encodeToString(salt));
        config.setProperty("keystore.password.iv",
                encoder.encodeToString(iv));
        config.setProperty("keystore.password.iter",
                String.valueOf(iterations));
    }
}