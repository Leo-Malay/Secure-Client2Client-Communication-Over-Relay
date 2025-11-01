import java.io.*;
import java.net.*;
import java.security.PublicKey;

public class Client {
    static Node node;
    static int nonce = -1;
    static Socket relaySocket;
    static PublicKey relayPublicKey;
    static DataInputStream dataInputStream;
    static DataOutputStream dataOutputStream;

    /* Connect to Relay */
    public static void connectToRelay(int port) {
        try {
            relaySocket = new Socket("localhost", port);

            InputStream clientInputStream = relaySocket.getInputStream();
            OutputStream clientOutputStream = relaySocket.getOutputStream();
            dataInputStream = new DataInputStream(clientInputStream);
            dataOutputStream = new DataOutputStream(clientOutputStream);
        } catch (Exception e) {
            System.out.println("[ERROR]: Something went wrong." + e);
        }
    }

    /* Handle Incoming Messages */
    public static void handleIncomingMessage() {
        while (true) {
            try {
                int length = dataInputStream.readInt();
                byte[] buffer = new byte[length];
                dataInputStream.readFully(buffer);
                Message msg = Message.fromByteArray(buffer);
                System.out.println("[INFO] Message received from <" + msg.senderId + ">");
                // Match message to respective handler
                switch (msg.messageType) {
                    case MessageType.REGISTRATION_ACK:
                        handleRegistrationAck(msg);
                        break;
                    case MessageType.SESSIONKEY_ACK:
                        handleSessionKeyAck(msg);
                        break;
                    default:
                        break;
                }
            } catch (EOFException e) {
                System.out.println("[SERVER] Connection closed by client");
                break;
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                break;
            } catch (Exception e) {
                System.out.println("[ERROR] Something went wrong");
                e.printStackTrace();
            }
        }
    }

    /* Init Registration */
    public static void initRegistration() throws Exception {
        // Preparing the message
        nonce = node.generateRandomNumber();
        Message message = new Message.Builder(node.nodeId, "Relay", MessageType.REGISTRATION).nonce(nonce)
                .publicKey(node.rsaPublicKey).build();
        // Sending the message to relay
        sendMessage("Relay", message);
    }

    /* Handle Registration Ack */
    public static void handleRegistrationAck(Message msg) throws Exception {
        if (nonce - 1 != msg.nonce) {
            System.out.println("[ERROR] Invalid Nonce Number");
        } else {
            System.out.println("[SUCCESS] Registration Successful");
        }
    }

    /* Init Session Key */
    public static void initSessionKey() throws Exception {
        // Prepare message
        Message session_init_msg = new Message.Builder(node.nodeId, "Bob", MessageType.SESSIONKEY_INIT).eph(2).nonce(3)
                .build();
        // Send message via relay
        sendMessage("Relay", session_init_msg);
    }

    /* Handle Session Key Ack */
    public static void handleSessionKeyAck(Message msg) {
        System.out.println("[INFO] Received Session INIT from " + msg.senderId);
    }

    /* Send Message */
    public static void sendMessage(String receiverId, Message msg) throws Exception {
        // Encrypt each message before sending
        // byte[] encryptedMessage = node.encryptRSA(receiverId, msg);
        byte[] encryptedMessage = msg.toByteArray();
        int messageLength = encryptedMessage.length;

        dataOutputStream.writeInt(messageLength);
        dataOutputStream.write(encryptedMessage);
        dataOutputStream.flush();
        System.out.println("[INFO] Message sent to <" + msg.receiverId + ">");
    }

    public static void main(String[] args) {
        try {
            if (args.length != 1) {
                System.out.println("Usage: java Client <Node_Name>");
                return;
            }
            node = new Node(args[0]);
            // Load public key of relay
            relayPublicKey = node.loadPublicKey("Relay");
            connectToRelay(5050);
            // Start listening
            Thread listener = new Thread(() -> {
                handleIncomingMessage();
            });
            listener.start();
            // Init Registration Process
            initRegistration();

            // Test Alice send Bob a message
            if (node.nodeId.equals("Alice")) {
                initSessionKey();
            }
        } catch (Exception e) {
            System.out.println("[ERROR]: Something went wrong");
            e.printStackTrace();
        }
    }
}
