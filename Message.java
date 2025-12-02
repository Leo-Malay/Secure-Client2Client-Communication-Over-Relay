import java.io.*;
import java.math.BigInteger;
import java.security.PublicKey;

public class Message implements Serializable {
    public String senderId;
    public String receiverId;
    public MessageType messageType;

    public BigInteger eph;
    public Integer nonce;
    public String verify;
    public String message;
    public PublicKey publicKey;

    private Message(Builder builder) {
        this.senderId = builder.senderId;
        this.receiverId = builder.receiverId;
        this.messageType = builder.messageType;
        this.eph = builder.eph;
        this.nonce = builder.nonce;
        this.verify = builder.verify;
        this.message = builder.message;
        this.publicKey = builder.publicKey;
    }

    public static class Builder {
        // Required fields
        private String senderId;
        private String receiverId;
        private MessageType messageType;
        // Optional fields
        private BigInteger eph;
        private Integer nonce;
        private String verify;
        private String message;
        private PublicKey publicKey;

        /* Message Builder class */
        public Builder(String senderId, String receiverId, MessageType messageType) {
            this.senderId = senderId;
            this.receiverId = receiverId;
            this.messageType = messageType;
        }

        /* Set optional eph */
        public Builder eph(BigInteger eph) {
            this.eph = eph;
            return this;
        }

        /* Set optional nonce */
        public Builder nonce(Integer nonce) {
            this.nonce = nonce;
            return this;
        }

        /* Set optional verify */
        public Builder verify(String verify) {
            this.verify = verify;
            return this;
        }

        /* Set optional message */
        public Builder message(String message) {
            this.message = message;
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
