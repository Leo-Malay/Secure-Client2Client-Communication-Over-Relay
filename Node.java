import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;
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
    public long sentCount = 0;
    public long recvCount = 0;

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

    public SecretKeySpec getSessionKey() {
        return this.sessionKey;
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

    /* Generate Signature */
    public void signMessage(Message msg) throws Exception {
        // Temporarily clear signature field
        msg.setSignature(null);

        // Serialize the message (without signature)
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(msg);
        oos.flush();
        byte[] data = bos.toByteArray();

        // Sign serialized bytes
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(this.rsaPrivateKey);
        s.update(data);
        byte[] sig = s.sign();

        // Restore signature to message
        msg.setSignature(sig);
    }

    /* Verify Signature */
    public boolean verifyMessage(Message msg) throws Exception {
        PublicKey senderPublicKey = this.neighbourPublicKey.get(msg.senderId);
        if (senderPublicKey == null)
            senderPublicKey = loadPublicKey(msg.senderId);
        byte[] sig = msg.sign;
        // Temporarily remove signature for verification
        msg.setSignature(null);

        // Serialize message (without signature)
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(msg);
        oos.flush();
        byte[] data = bos.toByteArray();

        // Verify
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(senderPublicKey);
        s.update(data);
        boolean ok = s.verify(sig);

        // Restore signature
        msg.setSignature(sig);

        return ok;
    }

    /* Generate Random Number */
    public int generateRandomNumber() {
        return (int) (Math.random() * 10000);
    }

    /* Encrypt Message */
    public byte[] encryptRSA(String receiverId, Message msg) throws Exception {
        PublicKey receiverPublicKey = this.neighbourPublicKey.get(receiverId);
        if (receiverPublicKey == null)
            receiverPublicKey = loadPublicKey(receiverId);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);

        byte[] data = msg.toByteArray();
        int originalLen = data.length;

        int keySizeBytes = ((RSAPublicKey) receiverPublicKey).getModulus().bitLength() / 8;
        int blockSize = keySizeBytes - 11;

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        // Write true data length (first 4 bytes)
        output.write(ByteBuffer.allocate(4).putInt(originalLen).array());

        int offset = 0;
        while (offset < originalLen) {
            int chunkSize = Math.min(blockSize, originalLen - offset);
            byte[] chunk = Arrays.copyOfRange(data, offset, offset + chunkSize);
            output.write(cipher.doFinal(chunk));
            offset += chunkSize;
        }

        return output.toByteArray();
    }

    /* Decrpyt Message */
    public byte[] decryptRSA(byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.rsaPrivateKey);

        int keySizeBytes = ((RSAPrivateKey) this.rsaPrivateKey).getModulus().bitLength() / 8;

        // FIRST 4 BYTES = original length
        ByteBuffer wrap = ByteBuffer.wrap(ciphertext, 0, 4);
        int originalLen = wrap.getInt();

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        int offset = 4;
        while (offset < ciphertext.length) {
            byte[] encBlock = Arrays.copyOfRange(ciphertext, offset, offset + keySizeBytes);
            byte[] decChunk = cipher.doFinal(encBlock);
            output.write(decChunk);
            offset += keySizeBytes;
        }

        // Truncate to EXACT original serialized data length
        byte[] allDec = output.toByteArray();
        return Arrays.copyOfRange(allDec, 0, originalLen);
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

    /* Encrypt using session key */
    /*
     * public String sessionEncrypt(String plaintext) throws Exception {
     * if (this.sessionKey == null)
     * throw new IllegalStateException("Session key not established");
     * 
     * byte[] plainBytes = plaintext.getBytes("UTF-8");
     * byte[] sessionKeyBytes = this.sessionKey.getEncoded();
     * 
     * MessageDigest sha = MessageDigest.getInstance("SHA-256");
     * byte[] current = sha.digest(sessionKeyBytes);
     * byte[] keystream = new byte[plainBytes.length];
     * int pos = 0;
     * 
     * // Extending keystream
     * while (pos < plainBytes.length) {
     * int copy = Math.min(current.length, plainBytes.length - pos);
     * System.arraycopy(current, 0, keystream, pos, copy);
     * pos += copy;
     * if (pos < plainBytes.length) {
     * current = sha.digest(current);
     * }
     * }
     * 
     * // XOR
     * byte[] cipherBytes = new byte[plainBytes.length];
     * for (int i = 0; i < plainBytes.length; i++) {
     * cipherBytes[i] = (byte) (plainBytes[i] ^ keystream[i]);
     * }
     * 
     * return Base64.getEncoder().encodeToString(cipherBytes);
     * }
     */
    /* Encrypt using session key */
    public String sessionEncrypt(String plaintext) throws Exception {
        if (this.sessionKey == null)
            throw new IllegalStateException("Session key not established");

        byte[] plainBytes = plaintext.getBytes("UTF-8");
        byte[] sessionKeyBytes = this.sessionKey.getEncoded();

        byte[] cnt = ByteBuffer.allocate(8).putLong(sentCount).array();
        byte[] combined = new byte[cnt.length + sessionKeyBytes.length];
        System.arraycopy(cnt, 0, combined, 0, cnt.length);
        System.arraycopy(sessionKeyBytes, 0, combined, cnt.length, sessionKeyBytes.length);
        // ---------------------------------

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] current = sha.digest(combined);
        byte[] keystream = new byte[plainBytes.length];
        int pos = 0;

        // Extending keystream
        while (pos < plainBytes.length) {
            int copy = Math.min(current.length, plainBytes.length - pos);
            System.arraycopy(current, 0, keystream, pos, copy);
            pos += copy;
            if (pos < plainBytes.length) {
                current = sha.digest(current);
            }
        }

        // XOR
        byte[] cipherBytes = new byte[plainBytes.length];
        for (int i = 0; i < plainBytes.length; i++) {
            cipherBytes[i] = (byte) (plainBytes[i] ^ keystream[i]);
        }

        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    /* Decrypt using session key */
    /*
     * public String sessionDecrypt(String ciphertext) throws Exception {
     * if (this.sessionKey == null)
     * throw new IllegalStateException("Session key not established");
     * 
     * byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);
     * byte[] sessionKeyBytes = this.sessionKey.getEncoded();
     * 
     * MessageDigest sha = MessageDigest.getInstance("SHA-256");
     * byte[] current = sha.digest(sessionKeyBytes);
     * byte[] keystream = new byte[cipherBytes.length];
     * int pos = 0;
     * 
     * while (pos < cipherBytes.length) {
     * int copy = Math.min(current.length, cipherBytes.length - pos);
     * System.arraycopy(current, 0, keystream, pos, copy);
     * pos += copy;
     * if (pos < cipherBytes.length) {
     * current = sha.digest(current);
     * }
     * }
     * 
     * byte[] plainBytes = new byte[cipherBytes.length];
     * for (int i = 0; i < cipherBytes.length; i++) {
     * plainBytes[i] = (byte) (cipherBytes[i] ^ keystream[i]);
     * }
     * 
     * return new String(plainBytes, "UTF-8");
     * }
     */
    /* Decrypt using session key */
    public String sessionDecrypt(String ciphertext) throws Exception {
        if (this.sessionKey == null)
            throw new IllegalStateException("Session key not established");

        byte[] cipherBytes = Base64.getDecoder().decode(ciphertext);
        byte[] sessionKeyBytes = this.sessionKey.getEncoded();

        byte[] cnt = ByteBuffer.allocate(8).putLong(recvCount).array();
        byte[] combined = new byte[cnt.length + sessionKeyBytes.length];
        System.arraycopy(cnt, 0, combined, 0, cnt.length);
        System.arraycopy(sessionKeyBytes, 0, combined, cnt.length, sessionKeyBytes.length);
        // ---------------------------------

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] current = sha.digest(combined);
        byte[] keystream = new byte[cipherBytes.length];
        int pos = 0;

        while (pos < cipherBytes.length) {
            int copy = Math.min(current.length, cipherBytes.length - pos);
            System.arraycopy(current, 0, keystream, pos, copy);
            pos += copy;
            if (pos < cipherBytes.length) {
                current = sha.digest(current);
            }
        }

        byte[] plainBytes = new byte[cipherBytes.length];
        for (int i = 0; i < cipherBytes.length; i++) {
            plainBytes[i] = (byte) (cipherBytes[i] ^ keystream[i]);
        }

        return new String(plainBytes, "UTF-8");
    }

}