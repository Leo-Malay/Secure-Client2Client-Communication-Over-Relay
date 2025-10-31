import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.HashMap;
import javax.crypto.Cipher;

public class Node {
    public String nodeId;
    protected PrivateKey rsaPrivateKey;
    protected PublicKey rsaPublicKey;
    protected HashMap<String, PublicKey> neighbourPublicKey = new HashMap<>();
    public final String keyDirectory = "./keys/";

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
            // Load PRIVATE key (PKCS#8)
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
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
        Path privateKeyFile = Path.of(this.keyDirectory, "private_" + nodeId);
        // Chacking if the file exists
        boolean privateKeyExists = Files.exists(privateKeyFile);
        if (!privateKeyExists) {
            System.out.println("[ERROR]: Key files not found");
            return null;
        } else {
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
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
}