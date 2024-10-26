import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration; 
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
                System.exit(1);
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
        System.out.println("  -transformation <cipherTransformation> (optional)");
        System.out.println("Example:");
        System.out.println("  java HybridFileEncryptor -enc secret.txt recipient.cer -symAlg AES -asymAlg RSA -transformation AES/CBC/PKCS5Padding");
    }

    private static void encryptMode(String[] args) throws Exception {
        if (args.length < 3) {
            usage();
            System.exit(1);
        }

        String inputFile = args[1];
        String certFile = args[2];
        String symAlgorithm = "AES";
        String asymAlgorithm = "RSA";
        String transformation = null; 

        // Parse options
        for (int i = 3; i < args.length; i++) {
            if ("-symAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                symAlgorithm = args[++i];
            } else if ("-asymAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                asymAlgorithm = args[++i];
            } else if ("-transformation".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                transformation = args[++i];
            } else {
                System.err.println("Unknown option: " + args[i]);
                usage();
                System.exit(1);
            }
        }

        // Determine cipher transformation
        String cipherTransformation = (transformation != null) ? transformation : symAlgorithm + "/CBC/PKCS5Padding";

        // Load and validate certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        try (FileInputStream fis = new FileInputStream(certFile)) {
            certificate = (X509Certificate) certFactory.generateCertificate(fis);
            certificate.checkValidity(); // Validate certificate
            System.out.println("Certificate " + certFile + " is valid.");
        }

        PublicKey publicKey = certificate.getPublicKey();

        // Generate symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance(symAlgorithm);
        // Set key size based on algorithm
        if ("AES".equalsIgnoreCase(symAlgorithm)) {
            keyGen.init(256); // Use 128, 192, or 256 bits
        } else if ("DES".equalsIgnoreCase(symAlgorithm)) {
            keyGen.init(56); // DES key size
        } else if ("DESede".equalsIgnoreCase(symAlgorithm) || "TripleDES".equalsIgnoreCase(symAlgorithm)) {
            keyGen.init(168); // 3DES key size
        } else {
            // Default key size or throw exception
            keyGen.init(128);
        }
        SecretKey symmetricKey = keyGen.generateKey();
        System.out.println("Symmetric Key Generated: " + Base64.encodeBase64String(symmetricKey.getEncoded()));

        // Encrypt the file content
        byte[] encryptedData = encryptFileContent(inputFile, symmetricKey, cipherTransformation);
        System.out.println("File encrypted successfully.");

        // Encrypt the symmetric key with the recipient's public key
        byte[] encryptedSymmetricKey = encryptSymmetricKey(symmetricKey, publicKey, asymAlgorithm);
        System.out.println("Symmetric Key Encrypted: " + Base64.encodeBase64String(encryptedSymmetricKey));

        // Save encrypted data and encrypted symmetric key to files (Base64-encoded)
        saveToFile("encrypted_data.enc", encryptedData);
        saveToFile("encrypted_key.enc", encryptedSymmetricKey);

        System.out.println("Encryption successful.");
        System.out.println("Encrypted data file: encrypted_data.enc");
        System.out.println("Encrypted key file: encrypted_key.enc");
    }

    private static void decryptMode(String[] args) throws Exception {
        if (args.length < 5) {
            usage();
            System.exit(1);
        }

        String encryptedFile = args[1];
        String encryptedKeyFile = args[2];
        String keystoreFile = args[3];
        String keystorePassword = args[4];
        String symAlgorithm = "AES";
        String asymAlgorithm = "RSA";
        String transformation = null; // Optional: allow full transformation string

        // Parse options
        for (int i = 5; i < args.length; i++) {
            if ("-symAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                symAlgorithm = args[++i];
            } else if ("-asymAlg".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                asymAlgorithm = args[++i];
            } else if ("-transformation".equalsIgnoreCase(args[i]) && i + 1 < args.length) {
                transformation = args[++i];
            } else {
                System.err.println("Unknown option: " + args[i]);
                usage();
                System.exit(1);
            }
        }

        // Determine cipher transformation
        String cipherTransformation = (transformation != null) ? transformation : symAlgorithm + "/CBC/PKCS5Padding";

        // Load private key from keystore
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            keystore.load(fis, keystorePassword.toCharArray());
        }
        String alias = null;
        Enumeration<String> aliases = keystore.aliases();
        if (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
        } else {
            throw new Exception("No aliases found in keystore.");
        }

        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, keystorePassword.toCharArray());
        System.out.println("Private Key Loaded: " + alias);

        // Decrypt the symmetric key
        byte[] encryptedSymmetricKey = readFromFile(encryptedKeyFile);
        SecretKey symmetricKey = decryptSymmetricKey(encryptedSymmetricKey, privateKey, asymAlgorithm, symAlgorithm);
        System.out.println("Symmetric Key Decrypted: " + Base64.encodeBase64String(symmetricKey.getEncoded()));

        // Decrypt the file content
        byte[] decryptedData = decryptFileContent(encryptedFile, symmetricKey, cipherTransformation);
        System.out.println("File decrypted successfully.");

        // Save decrypted data to file
        saveToFile("decrypted_output", decryptedData);
        System.out.println("Decryption successful.");
        System.out.println("Decrypted file: decrypted_output");
    }

    private static byte[] encryptFileContent(String inputFile, SecretKey symmetricKey, String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivParams);
        System.out.println("Encryption Cipher Initialized with IV: " + Base64.encodeBase64String(iv));

        try (FileInputStream fis = new FileInputStream(inputFile);
             ByteArrayOutputStream baos = new ByteArrayOutputStream();
             CipherOutputStream cos = new CipherOutputStream(baos, cipher)) {

            // Prepend IV to the encrypted data
            baos.write(iv);

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
            cos.flush();
            cos.close(); // Ensure all data is flushed, including padding
            return baos.toByteArray();
        }
    }

    private static byte[] decryptFileContent(String encryptedFile, SecretKey symmetricKey, String transformation) throws Exception {
        byte[] fileContent = readFromFile(encryptedFile);
        System.out.println("Encrypted Data Length: " + fileContent.length + " bytes");

        Cipher cipher = Cipher.getInstance(transformation);
        int blockSize = cipher.getBlockSize();

        if (fileContent.length < blockSize) {
            throw new Exception("Encrypted file is too short to contain an IV.");
        }

        // Extract IV from the beginning
        byte[] iv = new byte[blockSize];
        System.arraycopy(fileContent, 0, iv, 0, blockSize);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivParams);
        System.out.println("Decryption Cipher Initialized with IV: " + Base64.encodeBase64String(iv));

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
        return encryptedKey;
    }

    private static SecretKey decryptSymmetricKey(byte[] encryptedKey, PrivateKey privateKey, String algorithm, String symAlgorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = cipher.doFinal(encryptedKey);
        // Use the actual symmetric algorithm
        return new SecretKeySpec(decodedKey, symAlgorithm);
    }

    private static void saveToFile(String filename, byte[] data) throws IOException {
        byte[] encodedData = Base64.encodeBase64(data);
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(encodedData);
        }
        System.out.println("Saved " + filename + " (" + encodedData.length + " bytes, Base64-encoded).");
    }

    private static byte[] readFromFile(String filename) throws IOException {
        byte[] encodedData = Files.readAllBytes(Paths.get(filename));
        return Base64.decodeBase64(encodedData);
    }
}
