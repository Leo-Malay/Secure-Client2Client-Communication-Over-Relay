import java.io.*;
import java.net.*;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class Relay {
    static Node node;
    static ServerSocket server;
    static Map<String, DataOutputStream> clientMap;
    static Map<String, PublicKey> clientPublicMap;

    /* Function to handle any incoming messages to the Relay */
    public static void handleIncomingMessage(Message msg, DataOutputStream dataOutStream) throws Exception {
        switch (msg.messageType) {
            case REGISTRATION:
                if (!node.verifyMessage(msg)) {
                    System.out.println("[ERROR] Integrity Failed. Message signature mismatch.");
                } else {
                    handleRegistration(msg, dataOutStream);
                }
                break;
            default:
                relayMessage(msg);
                break;
        }
    }

    /* Handle client registration */
    public static void handleRegistration(Message msg, DataOutputStream dataOutStream) throws Exception {
        System.out.println("[INFO] Received Registration INIT message from <" + msg.senderId + ">");
        // Add the associated public key of client to the client map
        if (clientMap.containsKey(msg.senderId)) {
            System.out.println("[INFO] Client ID already present. Updating the public key");
        } else {
            // Adding node public key to map.
            clientPublicMap.put(msg.senderId, msg.publicKey);
            // Adding connection to map.
            clientMap.put(msg.senderId, dataOutStream);
        }
        // Send an Acknowledgement
        Message msg_ack = new Message.Builder(node.nodeId, msg.senderId, MessageType.REGISTRATION_ACK)
                .nonce(msg.nonce - 1).build();
        sendMessage(msg.senderId, msg_ack);
    }

    /* Message is not for relay, forward it to respective receiver */
    public static void relayMessage(Message msg) throws Exception {
        System.out.println("[INFO] Relaying message from <" + msg.senderId + "> --> <" + msg.receiverId + ">");
        // Determine who the receiver is
        String receiverId = msg.receiverId;
        // Relaying the message
        sendMessage(receiverId, msg);
    }

    /* Send the message to receiver */
    public static void sendMessage(String receiverId, Message msg) throws Exception {
        // Check if client is connected to us!
        if (!clientMap.containsKey(receiverId)) {
            System.out.println("[ERROR]: Client<" + receiverId + "> is not connected.");
        }

        DataOutputStream dataOutStream = clientMap.get(receiverId);
        // Encrypt each message before sending
        if (msg.messageType == MessageType.REGISTRATION_ACK) {
            node.signMessage(msg);
        }
        byte[] encryptedMessage = node.encryptRSA(receiverId, msg);
        int messageLength = encryptedMessage.length;

        dataOutStream.writeInt(messageLength);
        dataOutStream.write(encryptedMessage);
        dataOutStream.flush();
        System.out.println("[INFO] Message sent to <" + msg.receiverId + ">");
    }

    public static void main(String[] args) {
        try {
            // Initialize node and client mapp
            node = new Node("Relay");
            clientMap = new HashMap<String, DataOutputStream>();
            clientPublicMap = new HashMap<String, PublicKey>();
            // Load Keys
            node.checkAndLoadKeys();

            // Start the socket server
            server = new ServerSocket(5050);
            System.out.println("[SERVER] Started listening on port 5050");

            // Enter loop
            while (true) {
                Socket client = server.accept();
                // Start thread to handle the client connection
                Thread listener = new Thread(() -> {
                    try {
                        InputStream clientInputStream = client.getInputStream();
                        OutputStream clientOutputStream = client.getOutputStream();
                        DataInputStream dataInputStream = new DataInputStream(clientInputStream);
                        DataOutputStream dataOutputStream = new DataOutputStream(clientOutputStream);

                        while (!client.isClosed()) {
                            try {

                                int length = dataInputStream.readInt();
                                byte[] buffer = new byte[length];
                                dataInputStream.readFully(buffer);
                                // Message msg = Message.fromByteArray(buffer);
                                byte[] decryptedMessage = node.decryptRSA(buffer);
                                Message msg = Message.fromByteArray(decryptedMessage);
                                // Handle incoming message
                                handleIncomingMessage(msg, dataOutputStream);

                            } catch (EOFException e) {
                                System.out.println("[SERVER] Connection closed by client");
                                break;
                            } catch (IOException | ClassNotFoundException e) {
                                e.printStackTrace();
                                break;
                            }
                        }
                    } catch (Exception e) {
                        System.out.println("[ERROR]:" + e);
                        e.printStackTrace();
                    }
                });
                listener.start();
            }
        } catch (Exception e) {
            System.out.println("[ERROR]:" + e);
            e.printStackTrace();
        }

    }
}