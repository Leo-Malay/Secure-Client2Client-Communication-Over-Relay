import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

public class Relay {
    static Node node;
    static ServerSocket server;
    static Map<String, DataOutputStream> clientMap;

    public static void handleIncomingMessage(Message msg) {

    }

    public static void sendMessage(String receiverId, Message msg) throws Exception {
        // Check if client is connected to us!
        if (!clientMap.containsKey(receiverId)) {
            System.out.println("[ERROR]: Client<" + receiverId + "> is not connected.");
        }

        DataOutputStream dataOutStream = clientMap.get(receiverId);
        // preparing the message
        byte[] messageBuffer = msg.toByteArray();
        int messageLength = messageBuffer.length;

        dataOutStream.writeInt(messageLength);
        dataOutStream.write(messageBuffer);
        dataOutStream.flush();
        System.out.println("[INFO] Message sent from <" + msg.senderId + "> --> <" + msg.receiverId + ">");
    }

    public static void main(String[] args) {
        try {
            // Initialize node and client mapp
            node = new Node("Relay");
            clientMap = new HashMap<String, DataOutputStream>();
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
                    System.out.println("Accepted a connection");
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
                                Message msg = Message.fromByteArray(buffer);
                                // Handle incoming message
                                handleIncomingMessage(msg);

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