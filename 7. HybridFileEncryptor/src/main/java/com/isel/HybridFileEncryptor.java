package com.isel;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class HybridFileEncryptor {

    public static void main(String[] args) {
        if (args.length < 2) {
            usage();
            System.exit(1);
        }

        String mode = args[0];

        try {
            if ("-enc".equalsIgnoreCase(mode)) {
                encryptMode(args);
            } else if ("-dec".equalsIgnoreCase(mode)) {
                decryptMode(args);
            } else {
                usage();
            }
        } catch (Exception e) {
            System.err.println("Operation failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void usage() {
        System.out.println("Usage:");
        System.out.println("Encryption mode:");
        System.out.println("  java HybridFileEncryptor -enc <inputFile> <certificateFile> [options]");
        System.out.println("Decryption mode:");
        System.out.println("  java HybridFileEncryptor -dec <encryptedFile> <encryptedKeyFile> <keystoreFile> <keystorePassword> [options]");
        System.out.println("Options:");
        System.out.println("  -symAlg <symmetricAlgorithm> (default: AES)");
        System.out.println("  -asymAlg <asymmetricAlgorithm> (default: RSA)");
    }

    private static void encryptMode(String[] args) throws Exception {
        String inputFile = args[1];
        String certFile = args[2];
        String symAlgorithm = "AES";
        String asymAlgorithm = "RSA";

        for (int i = 3; i < args.length; i++) {
            if ("-symAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                symAlgorithm = args[++i];
            } else if ("-asymAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                asymAlgorithm = args[++i];
            }
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certFile)) {
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(fis);
            certificate.checkValidity();
            PublicKey publicKey = certificate.getPublicKey();

            KeyGenerator keyGen = KeyGenerator.getInstance(symAlgorithm);
            keyGen.init(256);
            SecretKey symmetricKey = keyGen.generateKey();

            byte[] encryptedData = encryptFileContent(inputFile, symmetricKey, symAlgorithm);
            byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, publicKey, asymAlgorithm);

            saveToFile("encrypted_data.enc", encryptedData);
            saveToFile("encrypted_key.enc", encryptedSymmetricKey);

            System.out.println("Encryption successful.");
        }
    }

    private static void decryptMode(String[] args) throws Exception {
        String encryptedFile = args[1];
        String encryptedKeyFile = args[2];
        String keystoreFile = args[3];
        String keystorePassword = args[4];
        String symAlgorithm = "AES";
        String asymAlgorithm = "RSA";

        for (int i = 5; i < args.length; i++) {
            if ("-symAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                symAlgorithm = args[++i];
            } else if ("-asymAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                asymAlgorithm = args[++i];
            }
        }

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keystore.load(fis, keystorePassword.toCharArray());
        }
        String alias = keystore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, keystorePassword.toCharArray());

        byte[] encryptedSymmetricKey = readFromFile(encryptedKeyFile);
        SecretKey symmetricKey = decryptSymmetricKey(encryptedSymmetricKey, privateKey, asymAlgorithm);

        byte[] decryptedData = decryptFileContent(encryptedFile, symmetricKey, symAlgorithm);
        saveToFile("decrypted_output", decryptedData);

        System.out.println("Decryption successful.");
    }

    private static byte[] encryptFileContent(String inputFile, SecretKey symmetricKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivParams);

        try (FileInputStream fis = new FileInputStream(inputFile);
             ByteArrayOutputStream baos = new ByteArrayOutputStream();
             CipherOutputStream cos = new CipherOutputStream(baos, cipher)) {

            baos.write(iv);
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
            cos.flush();
            return baos.toByteArray();
        }
    }

    private static byte[] decryptFileContent(String encryptedFile, SecretKey symmetricKey, String algorithm) throws Exception {
        byte[] fileContent = readFromFile(encryptedFile);

        Cipher cipher = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding");
        int blockSize = cipher.getBlockSize();

        byte[] iv = new byte[blockSize];
        System.arraycopy(fileContent, 0, iv, 0, blockSize);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivParams);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(fileContent, blockSize, fileContent.length - blockSize);
             CipherInputStream cis = new CipherInputStream(bais, cipher);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = cis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }
            return baos.toByteArray();
        }
    }

private static byte[] encryptSymmetricKey(SecretKey symmetricKey, PublicKey publicKey, String algorithm) throws Exception {
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());
    System.out.println("Symmetric Key Encrypted: " + Base64.encodeBase64String(encryptedKey));
    return encryptedKey;
}

private static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey, String algorithm) throws Exception {
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    byte[] decodedKey = cipher.doFinal(encryptedKey);
    System.out.println("Symmetric Key Decrypted: " + Base64.encodeBase64String(decodedKey));
    return new SecretKeySpec(decodedKey, "AES"); // Assuming AES symmetric key
}

    private static void saveToFile(String filename, byte[] data) throws IOException {
        byte[] encodedData = Base64.encodeBase64(data);
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(encodedData);
        }
    }

    private static byte[] readFromFile(String filename) throws IOException {
        byte[] encodedData = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filename));
        return Base64.decodeBase64(encodedData);
    }
}
