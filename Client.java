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
            System.out.println("[INFO] Connecting to Relay on port " + port + "...");
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
                Message msg = Message.fromByteArray(buffer);
                System.out.println("[INFO] Message received from <" + msg.senderId + "> - Type: " + msg.messageType);
                
                // Match message to respective handler
                switch (msg.messageType) {
                    case REGISTRATION_ACK:
                        System.out.println("[INFO] Received REGISTRATION_ACK message");
                        handleRegistrationAck(msg);
                        break;
                    case SESSIONKEY_INIT:
                        System.out.println("[INFO] Received SESSIONKEY_INIT message");
                        handleSessionKeyInit(msg);
                        break;
                    case SESSIONKEY_ACK:
                        System.out.println("[INFO] Received SESSIONKEY_ACK message");
                        handleSessionKeyAck(msg);
                        break;
                    case SESSIONKEY_VERIFY:
                        System.out.println("[INFO] Received SESSIONKEY_VERIFY message");
                        handleSessionKeyVerify(msg);
                        break;
                    case CHAT_MESSAGE:
                        System.out.println("[INFO] Received CHAT_MESSAGE");
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
        System.out.println("[INFO] Initiating registration with Relay...");
        
        // Preparing the message
        nonce = node.generateRandomNumber();
        System.out.println("[INFO] Generated nonce: " + nonce);
        
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
        System.out.println("[INFO] Processing registration acknowledgment...");
        
        if (nonce - 1 != msg.nonce) {
            System.out.println("[ERROR] Invalid Nonce Number - Expected: " + (nonce - 1) + ", Received: " + msg.nonce);
        } else {
            System.out.println("[SUCCESS] Registration Successful - Nonce verified");
            if (receiverId != null) {
                System.out.println("[INFO] Auto-initiating session key exchange with " + receiverId);
                initSessionKey(receiverId);
            }
        }
    }

    /* Init Session Key */
    public static void initSessionKey(String receiverId) throws Exception {
        System.out.println("[INFO] Initiating session key exchange with <" + receiverId + ">");
        
        // Prepare message
        System.out.println("[INFO] Generating ephemeral keys...");
        BigInteger eph = node.generateEphemeralKeys(g, p);
        
        System.out.println("[INFO] Generating nonce...");
        nonce = node.generateRandomNumber();
        
        System.out.println("[INFO] Building SESSIONKEY_INIT message...");
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
        System.out.println("[INFO] Processing SESSIONKEY_INIT from <" + msg.senderId + ">");
        
        System.out.println("[INFO] Generating ephemeral keys...");
        BigInteger eph = node.generateEphemeralKeys(g, p);
        
        // Derive the session key
        System.out.println("[INFO] Deriving session key...");
        node.deriveSessionKey(msg.eph.toByteArray(), p);
        
        // Prepare message
        System.out.println("[INFO] Encrypting verification value...");
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
        System.out.println("[INFO] Processing SESSIONKEY_ACK from <" + msg.senderId + ">");
        
        if (msg.nonce != nonce - 1) {
            System.out.println("[ERROR] Nonce mismatch - Possible replay attack detected!");
            System.out.println("[ERROR] Expected: " + (nonce - 1) + ", Received: " + msg.nonce);
            return;
        }
        
        System.out.println("[INFO] Nonce verified successfully");
        
        // Derive the session key
        System.out.println("[INFO] Deriving session key...");
        node.deriveSessionKey(msg.eph.toByteArray(), p);
        
        System.out.println("[INFO] Decrypting and verifying session key...");
        if (node.sessionDecrypt(msg.verify).equals("100")) {
            System.out.println("[SUCCESS] Session key verified - Keys match!");
            
            // Prepare Message
            System.out.println("[INFO] Sending final verification...");
            Message session_ack_msg = new Message.Builder(node.nodeId, msg.senderId, MessageType.SESSIONKEY_VERIFY)
                    .verify(node.sessionEncrypt("99"))
                    .build();
            
            // Send message via relay
            System.out.println("[INFO] Sending SESSIONKEY_VERIFY message to <" + msg.senderId + "> via Relay");
            sendMessage("Relay", session_ack_msg);
        } else {
            System.out.println("[ERROR] Session key verification failed - Keys don't match");
        }
    }

    /* Handle Session Key Verify */
    public static void handleSessionKeyVerify(Message msg) throws Exception {
        System.out.println("[INFO] Processing SESSIONKEY_VERIFY from <" + msg.senderId + ">");
        
        System.out.println("[INFO] Decrypting verification value...");
        if (node.sessionDecrypt(msg.verify).equals("99")) {
            System.out.println("[SUCCESS] Session key establishment complete!");
            System.out.println("[INFO] You can now send encrypted messages to <" + msg.senderId + ">");
        } else {
            System.out.println("[ERROR] Session key verification failed - Keys don't match");
        }
    }

    /* Send Message */
    public static void sendMessage(String receiverId, Message msg) throws Exception {
        System.out.println("[INFO] Preparing to send message to <" + receiverId + ">");
        
        // Encrypt each message before sending
        // byte[] encryptedMessage = node.encryptRSA(receiverId, msg);
        byte[] encryptedMessage = msg.toByteArray();
        int messageLength = encryptedMessage.length;

        dataOutputStream.writeInt(messageLength);
        dataOutputStream.write(encryptedMessage);
        dataOutputStream.flush();
        
        System.out.println("[SUCCESS] Message sent to <" + msg.receiverId + "> (Size: " + messageLength + " bytes)");
    }

    public static void handleChatMessage(Message msg) throws Exception {
        System.out.println("[INFO] Decrypting chat message from <" + msg.senderId + ">");
        String decrypted = node.sessionDecrypt(msg.message);
        System.out.println("[" + msg.senderId + "]: " + decrypted);
    }

    public static void sendChatMessage(String receiverId, String text) throws Exception {
        System.out.println("[INFO] Sending chat message to <" + receiverId + ">");
        String encrypted = node.sessionEncrypt(text);
        
        Message chatMsg = new Message.Builder(node.nodeId, receiverId, MessageType.CHAT_MESSAGE)
                .message(encrypted)
                .build();
        
        sendMessage("Relay", chatMsg);
    }

    public static void main(String[] args) {
        try {
            if (args.length < 1) {
                System.out.println("Usage: java Client <Node_Name> <Optional_Receiver_Name>");
                return;
            }
            
            System.out.println("========================================");
            System.out.println("       SECURE CHAT CLIENT");
            System.out.println("========================================");
            
            System.out.println("[INFO] Initializing node: " + args[0]);
            node = new Node(args[0]);
            
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
            
            System.out.println("[INFO] Starting user input thread...");
            System.out.println("[INFO] Type messages to send (or 'quit' to exit)");
            System.out.println("========================================");
            
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
            
        } catch (Exception e) {
            System.out.println("[ERROR] Fatal error in main");
            e.printStackTrace();
        }
    }
}