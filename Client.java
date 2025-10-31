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

            while (true) {
                // Handle other stasks.
            }
        } catch (Exception e) {
            System.out.println("[ERROR]: Something went wrong." + e);
        }
    }

    /* Init Registration */
    public void InitRegistration() {
    }

    /* Init Session Key */
    public void InitSessionKey() {
    }

    /* Handle Session Key Ack */
    public void HandleSessionKeyAck() {
    }

    public static void main(String[] args) {
        node = new Node("ClientA");

        connectToRelay(5050);
    }
}
