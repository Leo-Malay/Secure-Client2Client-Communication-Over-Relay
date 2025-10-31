import java.io.*;
import java.security.PublicKey;

public class Message implements Serializable {
    public String senderId;
    public String receiverId;
    public int nonce;
    public MessageType messageType;
    public PublicKey publicKey;

    /* Constructor for registration messages */
    public Message(String senderId, String receiverId, Integer nonce, PublicKey publicKey) {
        this.messageType = MessageType.REGISTRATION;
        this.senderId = senderId;
        this.receiverId = receiverId;
        this.nonce = nonce;
        this.publicKey = publicKey;
    }

    /* Constructor for registration acknowledgment messages */
    public Message(String senderId, String receiverId, Integer nonce) {
        this.messageType = MessageType.REGISTRATION_ACK;
        this.senderId = senderId;
        this.receiverId = receiverId;
        this.nonce = nonce;
    }

    /* Convert object to byte array */
    public byte[] toByteArray() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream)) {
            objectOutputStream.writeObject(this);
        }
        return byteArrayOutputStream.toByteArray();
    }

    /* Generate object from byte array */
    public static Message fromByteArray(byte[] data) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(data);
                ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream)) {
            return (Message) objectInputStream.readObject();
        }
    }
}
