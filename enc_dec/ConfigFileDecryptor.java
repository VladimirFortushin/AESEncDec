package encrypt;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Base64;

public class ConfigFileDecryptor {

    public static void main(String[] args) throws Exception {
        String encryptedFile = "test.txt.enc";
        String keystoreFile = "test.jks";
        String configFile = "";
        String password = "";

        Properties config = new Properties();
        try (FileInputStream fis = new FileInputStream(configFile)) {
            config.load(fis);
        }
        String decryptedPassword = decryptPasswordFromConfig(config, password);
        SecretKey fileKey = loadKeyFromKeystore(keystoreFile, decryptedPassword);
        String decryptedContent = decryptFileToString(encryptedFile, fileKey);
        System.out.println(decryptedContent);
    }

    private static String decryptPasswordFromConfig(Properties config, String password) {
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] encryptedPassword = decoder.decode(config.getProperty("keystore.password.enc"));
        byte[] salt = decoder.decode(config.getProperty("keystore.password.salt"));
        byte[] iv = decoder.decode(config.getProperty("keystore.password.iv"));
        int iterations = Integer.parseInt(config.getProperty("keystore.password.iter"));
        if (verifyPassword(password, encryptedPassword, salt, iv, iterations)) {
            return password;
        } else {
            throw new SecurityException("incorrect password");
        }
    }

    private static boolean verifyPassword(String password, byte[] encryptedData,
                                          byte[] salt, byte[] iv, int iterations) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
            byte[] decrypted = cipher.doFinal(encryptedData);
            String decryptedPassword = new String(decrypted, StandardCharsets.UTF_8);
            return password.equals(decryptedPassword);
        } catch (Exception e) {
            return false;
        }
    }

    private static SecretKey loadKeyFromKeystore(String keystoreFile, String password)
            throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");

        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            ks.load(fis, password.toCharArray());
        }
        KeyStore.ProtectionParameter entryPassword =
                new KeyStore.PasswordProtection(password.toCharArray());
        KeyStore.SecretKeyEntry entry =
                (KeyStore.SecretKeyEntry) ks.getEntry("fileEncryptionKey", entryPassword);

        return entry.getSecretKey();
    }

    private static String decryptFileToString(String inputFile, SecretKey key)
            throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] iv = new byte[16];
            int bytesRead = fis.read(iv);
            if (bytesRead != 16) {
                throw new IOException("bytesRead != 16");
            }

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                byte[] buffer = new byte[4096];
                while ((bytesRead = cis.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                return baos.toString(StandardCharsets.UTF_8);
            }
        }
    }
}
