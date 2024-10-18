import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileHashGenerator {
    private static final int BUFFER_SIZE = 8192; // 8KB buffer

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java FileHashGenerator <filename> <algorithm1> [<algorithm2> ...]");
            System.exit(1);
        }

        String filename = args[0];

        // Initialize MessageDigest instances for each algorithm
        MessageDigest[] digests = new MessageDigest[args.length - 1];
        for (int i = 1; i < args.length; i++) {
            try {
                digests[i - 1] = MessageDigest.getInstance(args[i]);
            } catch (NoSuchAlgorithmException e) {
                System.err.println("Algorithm not found: " + args[i]);
                System.exit(1);
            }
        }

        // Read the file and update digests
        try (FileInputStream fis = new FileInputStream(filename)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                for (MessageDigest md : digests) {
                    md.update(buffer, 0, bytesRead);
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to read file: " + filename);
            System.exit(1);
        }

        // Output the hash values
        for (int i = 0; i < digests.length; i++) {
            String algorithm = args[i + 1];
            byte[] hashBytes = digests[i].digest();
            String hashHex = bytesToHex(hashBytes);
            System.out.println(algorithm + " = " + hashHex);
        }
    }

    // Utility method to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
