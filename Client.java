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
            if (receiverId != null) {
                initSessionKey(receiverId);
            }
        }
    }

    /* Init Session Key */
    public static void initSessionKey(String receiverId) throws Exception {
        System.out.println("INIT Session Key");
        // Prepare message
        BigInteger eph = node.generateEphemeralKeys(g, p);
        System.out.println("1");
        nonce = node.generateRandomNumber();
        System.out.println("2");
        Message session_init_msg = new Message.Builder(node.nodeId, receiverId, MessageType.SESSIONKEY_INIT).eph(eph)
                .nonce(nonce)
                .build();
        System.out.println("3");
        // Send message via relay
        System.out.println("Sending Session Key INIT");
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
        sendMessage("Relay", session_ack_msg);
    }

    /* Handle Session Key Ack */
    public static void handleSessionKeyAck(Message msg) throws Exception {
        if (msg.nonce != nonce - 1) {
            System.out.println("[ERROR]: Replay Attack Detected");
        }
        // Derive the session key
        node.deriveSessionKey(msg.eph.toByteArray(), p);
        if (node.sessionDecrypt(msg.verify).equals("100")) {
            // Prepare Message
            Message session_ack_msg = new Message.Builder(node.nodeId, msg.senderId, MessageType.SESSIONKEY_VERIFY)
                    .verify(node.sessionEncrypt("99"))
                    .build();
            // Send message via relay
            sendMessage("Relay", session_ack_msg);
        } else {
            System.out.println("[ERROR]: Invalid session key generated at both ends");
        }
    }

    /* Handle Session Key Verify */
    public static void handleSessionKeyVerify(Message msg) throws Exception {
        if (node.sessionDecrypt(msg.verify).equals("99")) {
            // Prepare Message
            System.out.println("[INFO]: Session generated successfully");
        } else {
            System.out.println("[ERROR]: Invalid session key generated at both ends");
        }
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

    public static void handleChatMessage(Message msg) throws Exception {
        String decrypted = node.sessionDecrypt(msg.message);
        System.out.println("[" + msg.senderId + "]: " + decrypted);
   }

    public static void sendChatMessage(String receiverId, String text) throws Exception {
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
            // Init Session Key
            if (args.length > 1) {
                receiverId = args[1];
            }
            
            Thread inputThread = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
                    String input;
                    while ((input = reader.readLine()) != null) {
                        if ("quit".equals(input)) {
                            System.out.println("[INFO] Shutting down...");
                            System.exit(0);
                        }
                        if (receiverId != null && node.getSessionKey() != null) {
                            sendChatMessage(receiverId, input);
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
            inputThread.start();
            
        } catch (Exception e) {
            System.out.println("[ERROR]: Something went wrong");
            e.printStackTrace();
        }
    }
}
