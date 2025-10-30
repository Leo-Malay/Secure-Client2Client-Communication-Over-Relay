import java.io.*;
import java.net.*;

public class Client {
    static Node node;
    static Socket relaySocket;

    /* Connect to Relay */
    public static void connectToRelay(int port) {
        try {
            relaySocket = new Socket("localhost", port);

            InputStream clientInputStream = relaySocket.getInputStream();
            OutputStream clientOutputStream = relaySocket.getOutputStream();
            DataInputStream dataInputStream = new DataInputStream(clientInputStream);
            DataOutputStream dataOutputStream = new DataOutputStream(clientOutputStream);

            System.out.println("Sending the message");
            // Making a sample message
            Message msg = new Message("ClientA");
            dataOutputStream.writeInt(msg.toByteArray().length);
            dataOutputStream.write(msg.toByteArray());
            dataOutputStream.flush();
            System.out.println("Message sent");
            while (true) {
                // Reading Incoming Message.
                int length = dataInputStream.readInt();
                byte[] buffer = new byte[length];
                dataInputStream.readFully(buffer);
                Message msg1 = Message.fromByteArray(buffer);

                System.out.println("SenderId:" + msg1.senderId);
                System.out.println("SeqId:" + msg1.seqId);
            }
        } catch (Exception e) {
            System.out.println("[ERROR]: Something went wrong." + e);
        }
    }

    /* Init Registration */
    public void InitRegistration() {
    }

    /* Handle Registration */
    public void HandleRegistration() {
    }

    /* Init Session Key */
    public void InitSessionKey() {
    }

    /* Handle Session Key */
    public void HandleSessionKey() {
    }

    /* Handle Session Key Ack */
    public void HandleSessionKeyAck() {
    }

    public static void main(String[] args) {
        node = new Node("ClientA");

        connectToRelay(5050);
    }
}
