import java.io.*;
import java.security.PublicKey;

public class Message implements Serializable {
    public String senderId;
    public String receiverId;
    public MessageType messageType;

    public Integer eph;
    public Integer nonce;
    public PublicKey publicKey;

    private Message(Builder builder) {
        this.senderId = builder.senderId;
        this.receiverId = builder.receiverId;
        this.messageType = builder.messageType;
        this.eph = builder.eph;
        this.nonce = builder.nonce;
        this.publicKey = builder.publicKey;
    }

    public static class Builder {
        // Required fields
        private String senderId;
        private String receiverId;
        private MessageType messageType;
        // Optional fields
        private Integer eph;
        private Integer nonce;
        private PublicKey publicKey;

        /* Message Builder class */
        public Builder(String senderId, String receiverId, MessageType messageType) {
            this.senderId = senderId;
            this.receiverId = receiverId;
            this.messageType = messageType;
        }

        /* Set optional eph */
        public Builder eph(Integer eph) {
            this.eph = eph;
            return this;
        }

        /* Set optional nonce */
        public Builder nonce(Integer nonce) {
            this.nonce = nonce;
            return this;
        }

        /* Set optional publicKey */
        public Builder publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        /* Build the message object */
        public Message build() {
            return new Message(this);
        }
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
