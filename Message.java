import java.io.*;

public class Message implements Serializable {
    public String senderId;
    public String receiverId;
    public int seqId;

    public Message(String senderId) {
        this.senderId = senderId;
        this.seqId = 0;
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
