import java.io.IOException;
import java.nio.file.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
    public void GenerateRSAKeys() throws IOException, NoSuchAlgorithmException {
        // Generate RSA Keys
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        // Generate and store key pairs
        this.rsaPrivateKey = keyPair.getPrivate();
        this.rsaPublicKey = keyPair.getPublic();
        // Saving the newly generate key file.
        SaveKeyFile();
    }

    /* Save Newly generate keys to the file */
    private void SaveKeyFile() throws IOException {
        Path privateKeyFile = Path.of(this.keyDirectory, "private_" + this.nodeId);
        Files.write(privateKeyFile, this.rsaPrivateKey.getEncoded(), StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING);
        System.out.println("[INFO]: Private key stored at path:" + privateKeyFile.toAbsolutePath());
    }

    /* Change and Load keys from the directory */
    public void CheckAndLoadKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path privateKeyFile = Path.of(this.keyDirectory, "private_" + this.nodeId);
        // Chacking if the file exists
        boolean privateKeyExists = Files.exists(privateKeyFile);
        if (!privateKeyExists) {
            System.out.println("[ERROR]: Key files not found");
            // Since key is not present, generating it.
            GenerateRSAKeys();
        } else {
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.rsaPrivateKey = kf.generatePrivate(privateKeySpec);
            this.rsaPublicKey = kf.generatePublic(privateKeySpec);
            System.out.println("[INFO] Private and Public keys loaded");
        }
    }

    /* Load the public key of the neighbouring node */
    public PublicKey LoadPublicKey(String nodeId)
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

    /* Encrypt Message */
    public byte[] EncryptRSA(String receiverId, Message msg) throws Exception {
        PublicKey receiverPublicKey = null;
        // Check if we have the public key
        boolean keyExists = this.neighbourPublicKey.containsKey(receiverId);
        if (!keyExists) {
            // Loading the key
            receiverPublicKey = LoadPublicKey(receiverId);
        }
        // Encrypting
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        return cipher.doFinal(msg.toByteArray());

    }

    /* Decrpyt Message */
    public byte[] DecryptRSA(Message msg) throws Exception {
        // Decrypting
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.rsaPrivateKey);
        return cipher.doFinal(msg.toByteArray());
    }
}