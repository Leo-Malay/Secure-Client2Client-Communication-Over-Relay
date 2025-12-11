import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.PublicKey;

public class Client {
    static Node node;
    static int nonce;
    static BigInteger g = BigInteger.valueOf(5);
    static BigInteger p = BigInteger.valueOf(519307);
    static Socket relaySocket;
    static PublicKey relayPublicKey;
    static DataInputStream dataInputStream;
    static DataOutputStream dataOutputStream;
    static String receiverId = null;

    /* Connect to Relay */
    public static void connectToRelay(int port) {
        try {
            relaySocket = new Socket("localhost", port);

            InputStream clientInputStream = relaySocket.getInputStream();
            OutputStream clientOutputStream = relaySocket.getOutputStream();
            dataInputStream = new DataInputStream(clientInputStream);
            dataOutputStream = new DataOutputStream(clientOutputStream);

            System.out.println("[SUCCESS] Connected to Relay successfully");
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to connect to Relay: " + e);
        }
    }

    /* Handle Incoming Messages */
    public static void handleIncomingMessage() {
        System.out.println("[INFO] Message listener thread started");
        while (true) {
            try {
                int length = dataInputStream.readInt();
                byte[] buffer = new byte[length];
                dataInputStream.readFully(buffer);
                byte[] decryptedMessage = node.decryptRSA(buffer);
                Message msg = Message.fromByteArray(decryptedMessage);
                // Decrypt Message Data

                System.out.println("[INFO] Message received from <" + msg.senderId + "> - Type: " + msg.messageType);

                // Match message to respective handler
                switch (msg.messageType) {
                    case REGISTRATION_ACK:
                        handleRegistrationAck(msg);
                        break;
                    case SESSIONKEY_INIT:
                        handleSessionKeyInit(msg);
                        break;
                    case SESSIONKEY_ACK:
                        handleSessionKeyAck(msg);
                        break;
                    case SESSIONKEY_VERIFY:
                        handleSessionKeyVerify(msg);
                        break;
                    case CHAT_MESSAGE:
                        handleChatMessage(msg);
                        break;
                    default:
                        System.out.println("[WARNING] Unknown message type received: " + msg.messageType);
                        break;
                }
            } catch (EOFException e) {
                System.out.println("[INFO] Connection closed by server");
                break;
            } catch (IOException | ClassNotFoundException e) {
                System.out.println("[ERROR] I/O error in message handler");
                e.printStackTrace();
                break;
            } catch (Exception e) {
                System.out.println("[ERROR] Unexpected error in message handler");
                e.printStackTrace();
            }
        }
    }

    /* Init Registration */
    public static void initRegistration() throws Exception {
        // Preparing the message
        nonce = node.generateRandomNumber();
        Message message = new Message.Builder(node.nodeId, "Relay", MessageType.REGISTRATION)
                .nonce(nonce)
                .publicKey(node.rsaPublicKey)
                .build();

        // Sending the message to relay
        System.out.println("[INFO] Sending REGISTRATION message to Relay");
        sendMessage("Relay", message);
    }

    /* Handle Registration Ack */
    public static void handleRegistrationAck(Message msg) throws Exception {
        if (nonce - 1 != msg.nonce) {
            System.out.println("[ERROR] Invalid Nonce Number");
        } else {
            System.out.println("[SUCCESS] Relay Registration Successful");
            if (receiverId != null) {
                initSessionKey(receiverId);
            }
        }
    }

    /* Init Session Key */
    public static void initSessionKey(String receiverId) throws Exception {

        // Prepare message
        BigInteger eph = node.generateEphemeralKeys(g, p);
        nonce = node.generateRandomNumber();
        Message session_init_msg = new Message.Builder(node.nodeId, receiverId, MessageType.SESSIONKEY_INIT)
                .eph(eph)
                .nonce(nonce)
                .build();

        // Send message via relay
        System.out.println("[INFO] Sending SESSIONKEY_INIT message to <" + receiverId + "> via Relay");
        sendMessage("Relay", session_init_msg);
    }

    /* Handle Session Key Init */
    public static void handleSessionKeyInit(Message msg) throws Exception {

        BigInteger eph = node.generateEphemeralKeys(g, p);

        // Derive the session key
        node.deriveSessionKey(msg.eph.toByteArray(), p);

        // Prepare message
        Message session_ack_msg = new Message.Builder(node.nodeId, msg.senderId, MessageType.SESSIONKEY_ACK)
                .eph(eph)
                .nonce(msg.nonce - 1)
                .verify(node.sessionEncrypt("100"))
                .build();

        // Send message via relay
        System.out.println("[INFO] Sending SESSIONKEY_ACK message to <" + msg.senderId + "> via Relay");
        sendMessage("Relay", session_ack_msg);
    }

    /* Handle Session Key Ack */
    public static void handleSessionKeyAck(Message msg) throws Exception {

        if (msg.nonce != nonce - 1) {
            System.out.println("[ERROR] Nonce mismatch - Possible replay attack detected!");
            return;
        }

        // Derive the session key
        node.deriveSessionKey(msg.eph.toByteArray(), p);
        if (node.sessionDecrypt(msg.verify).equals("100")) {
            System.out.println("[SUCCESS] Session key verified - Keys match!");
            receiverId = msg.senderId;
            startChatThread();

            // Prepare Message
            Message session_ack_msg = new Message.Builder(node.nodeId, msg.senderId, MessageType.SESSIONKEY_VERIFY)
                    .verify(node.sessionEncrypt("99"))
                    .build();

            // Send message via relay
            sendMessage("Relay", session_ack_msg);
        } else {
            System.out.println("[ERROR] Session key verification failed - Keys don't match");
        }
    }

    /* Handle Session Key Verify */
    public static void handleSessionKeyVerify(Message msg) throws Exception {

        if (node.sessionDecrypt(msg.verify).equals("99")) {
            receiverId = msg.senderId;
            System.out.println("[SUCCESS] Session key establishment complete!");
            System.out.println("[INFO] You can now send encrypted messages to <" + msg.senderId + ">");
            startChatThread();
        } else {
            System.out.println("[ERROR] Session key verification failed - Keys don't match");
        }
    }

    /* Send Message */
    public static void sendMessage(String receiverId, Message msg) throws Exception {
        // Encrypt each message before sending
        byte[] encryptedMessage = node.encryptRSA(receiverId, msg);
        int messageLength = encryptedMessage.length;

        dataOutputStream.writeInt(messageLength);
        dataOutputStream.write(encryptedMessage);
        dataOutputStream.flush();

        System.out.println("[SUCCESS] Message sent to <" + msg.receiverId + "> (Size: " + messageLength + " bytes)");
    }

    public static void handleChatMessage(Message msg) throws Exception {
        System.out.println("MessageId:" + msg.messageId + " | Recv Count:" + node.recvCount);
        if (msg.messageId != node.recvCount) {
            System.out.println("[ERROR] Replay Attack Detected. Message Received Again!");
            return;
        }
        node.recvCount += 1;
        System.out.println("[INFO] Decrypting chat message from <" + msg.senderId + ">");
        String decrypted = node.sessionDecrypt(msg.message);
        System.out.println("[" + msg.senderId + "]: " + decrypted);
    }

    public static void sendChatMessage(String receiverId, String text) throws Exception {
        System.out.println("[INFO] Sending chat message to <" + receiverId + ">");
        String encrypted = node.sessionEncrypt(text);
        if (text.equals("CTRL+R")) {
            // Send Fake Replay
            node.sentCount -= 1;
        }
        Message chatMsg = new Message.Builder(node.nodeId, receiverId, MessageType.CHAT_MESSAGE)
                .message(encrypted).messageId(node.sentCount)
                .build();
        node.sentCount += 1;

        sendMessage("Relay", chatMsg);
    }

    public static void startChatThread() {
        System.out.println("[INFO] Starting Chat, Type messages to send (or 'quit' to exit)\n");

        Thread inputThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                String input;
                while ((input = reader.readLine()) != null) {
                    if ("quit".equals(input)) {
                        System.out.println("[INFO] Shutting down client...");
                        System.exit(0);
                    }
                    if (receiverId != null && node.getSessionKey() != null) {
                        sendChatMessage(receiverId, input);
                    } else if (receiverId == null) {
                        System.out.println("[WARNING] No receiver specified. Cannot send message.");
                    } else if (node.getSessionKey() == null) {
                        System.out.println("[WARNING] Session key not established yet. Please wait...");
                    }
                }
            } catch (Exception e) {
                System.out.println("[ERROR] Input thread error");
                e.printStackTrace();
            }
        });
        inputThread.start();
    }

    public static void main(String[] args) {
        try {
            if (args.length < 1) {
                System.out.println("Usage: java Client <Node_Name> <Optional_Receiver_Name>");
                return;
            }

            System.out.println("[INFO] Initializing node: " + args[0]);
            node = new Node(args[0]);

            // Load Keys
            node.checkAndLoadKeys();
            // Load public key of relay
            System.out.println("[INFO] Loading Relay public key...");
            relayPublicKey = node.loadPublicKey("Relay");
            System.out.println("[SUCCESS] Relay public key loaded");

            connectToRelay(5050);

            // Start listening
            System.out.println("[INFO] Starting message listener thread...");
            Thread listener = new Thread(() -> {
                handleIncomingMessage();
            });
            listener.start();

            // Init Registration Process
            initRegistration();

            // Init Session Key
            if (args.length > 1) {
                receiverId = args[1];
                System.out.println("[INFO] Target receiver set to: " + receiverId);
            } else {
                System.out.println("[INFO] No receiver specified - waiting for incoming connections");
            }

        } catch (Exception e) {
            System.out.println("[ERROR] Fatal error in main");
            e.printStackTrace();
        }
    }
}