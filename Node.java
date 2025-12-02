import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Node {
    public String nodeId;
    protected PrivateKey rsaPrivateKey;
    protected PublicKey rsaPublicKey;
    protected HashMap<String, PublicKey> neighbourPublicKey = new HashMap<>();
    public final String keyDirectory = "./keys/";
    private BigInteger a = null;
    private BigInteger eph = null;
    private SecretKeySpec sessionKey = null;
    private SecureRandom rng = new SecureRandom();

    /* Node class constructor */
    public Node(String nodeId) {
        this.nodeId = nodeId;
    }

    /* Generate RSA public and private key */
    public void generateRSAKeys() throws IOException, NoSuchAlgorithmException {
        // Generate RSA Keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        // Generate and store key pairs
        this.rsaPrivateKey = keyPair.getPrivate();
        this.rsaPublicKey = keyPair.getPublic();
        // Saving the newly generate key file.
        saveKeyFile();
    }

    /* Save Newly generate keys to the file */
    private void saveKeyFile() throws IOException {
        // Create directory if not found
        Files.createDirectories(Path.of(this.keyDirectory));

        // Create private key file and save.
        Path privateKeyFile = Path.of(this.keyDirectory, "private_" + this.nodeId);
        Files.write(privateKeyFile, this.rsaPrivateKey.getEncoded(), StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);

        // Create public key file and save.
        Path publicKeyFile = Path.of(this.keyDirectory, "public_" + this.nodeId);
        Files.write(publicKeyFile, this.rsaPublicKey.getEncoded(), StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);

        System.out.println("[INFO]: Private key stored at path:" + privateKeyFile.toAbsolutePath());
    }

    /* Change and Load keys from the directory */
    public void checkAndLoadKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path privateKeyFile = Path.of(this.keyDirectory, "private_" + this.nodeId);
        Path publicKeyFile = Path.of(this.keyDirectory, "public_" + this.nodeId);
        // Chacking if the file exists
        boolean privateKeyExists = Files.exists(privateKeyFile);
        boolean publicKeyExists = Files.exists(privateKeyFile);
        if (!privateKeyExists || !publicKeyExists) {
            System.out.println("[ERROR]: Key files not found");
            // Since key is not present, generating it.
            generateRSAKeys();
        } else {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            // Load PRIVATE key (PKCS#8)
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            this.rsaPrivateKey = kf.generatePrivate(privateKeySpec);

            // Load PUBLIC key (X.509)
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            this.rsaPublicKey = kf.generatePublic(publicKeySpec);

            System.out.println("[INFO] Private and Public keys loaded");
        }
    }

    /* Load the public key of the neighbouring node */
    public PublicKey loadPublicKey(String nodeId)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path publicKeyFile = Path.of(this.keyDirectory, "public_" + nodeId);
        // Chacking if the file exists
        boolean publicKeyExists = Files.exists(publicKeyFile);
        if (!publicKeyExists) {
            System.out.println("[ERROR]: Key files not found");
            return null;
        } else {
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile);
            X509EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            System.out.println("[INFO] Loaded Public key of " + nodeId);
            return kf.generatePublic(privateKeySpec);
        }
    }

    /* Generate Random Number */
    public int generateRandomNumber() {
        return (int) (Math.random() * 10000);
    }

    /* Encrypt Message */
    public byte[] encryptRSA(String receiverId, Message msg) throws Exception {
        PublicKey receiverPublicKey = null;
        // Check if we have the public key
        boolean keyExists = this.neighbourPublicKey.containsKey(receiverId);
        if (!keyExists) {
            // Loading the key
            receiverPublicKey = loadPublicKey(receiverId);
        }
        // Encrypting
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        return cipher.doFinal(msg.toByteArray());
    }

    /* Decrpyt Message */
    public byte[] decryptRSA(Message msg) throws Exception {
        // Decrypting
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.rsaPrivateKey);
        return cipher.doFinal(msg.toByteArray());
    }

    /* Generate and Fetch EPH */
    public BigInteger generateEphemeralKeys(BigInteger g, BigInteger p) {
        int bits = 256;

        // Select valid random number
        BigInteger candidate;
        do {
            candidate = new BigInteger(bits, rng);
        } while (candidate.signum() <= 0);

        this.a = candidate;
        this.eph = g.modPow(this.a, p);
        return this.eph;
    }

    /* Deriving Session Key */
    public void deriveSessionKey(byte[] eph, BigInteger p) throws Exception {
        BigInteger peerEPH = new BigInteger(1, eph);

        if (peerEPH.compareTo(BigInteger.ONE) <= 0 || peerEPH.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("Invalid peer EPH");
        }

        BigInteger shared = peerEPH.modPow(this.a, p);
        this.a = null;

        // Derive AES key from shared secret via SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] raw = shared.toByteArray();
        byte[] hash = sha256.digest(raw);

        // Use first 16 bytes for AES-128 (or use 32 bytes for AES-256)
        byte[] keyBytes = Arrays.copyOf(hash, 16);
        this.sessionKey = new SecretKeySpec(keyBytes, "AES");

        Arrays.fill(hash, (byte) 0);
        Arrays.fill(raw, (byte) 0);
    }

    /* Encrypt message using session key */
    public String sessionEncrypt(String plaintext) throws Exception {
        if (this.sessionKey == null)
            throw new IllegalStateException("Session key not established");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12]; // 96-bit IV recommended for GCM
        rng.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit tag
        cipher.init(Cipher.ENCRYPT_MODE, this.sessionKey, spec);
        byte[] ct = cipher.doFinal(plaintext.getBytes("UTF-8"));

        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);

        return Base64.getEncoder().encodeToString(out);
    }

    /* Decrypt message using session key */
    public String sessionDecrypt(String ciphertext) throws Exception {
        if (this.sessionKey == null)
            throw new IllegalStateException("Session key not established");

        byte[] all = Base64.getDecoder().decode(ciphertext);
        if (all.length < 12)
            throw new IllegalArgumentException("Malformed ciphertext");

        byte[] iv = new byte[12];
        System.arraycopy(all, 0, iv, 0, 12);
        byte[] ct = new byte[all.length - 12];
        System.arraycopy(all, 12, ct, 0, ct.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, this.sessionKey, spec);
        byte[] pt = cipher.doFinal(ct);
        return new String(pt, "UTF-8");
    }
}