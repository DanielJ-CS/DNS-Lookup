
import java.io.ByteArrayOutputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Random;

/**
 *
 */

/**
 * @author Donald Acton
 *         This example is adapted from Kurose & Ross
 *         Feel free to modify and rearrange code as you see fit
 */
public class DNSlookup {


    static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
    static final int MAX_PERMITTED_ARGUMENT_COUNT = 3;
    public static int counterOfSending = 0;
    public static boolean noResult = true;


    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {

        String fqdn;
        int argCount = args.length;
        boolean IPV6Query = false;
        boolean tracingOn = false;
        InetAddress rootNameServer;

        if (argCount < MIN_PERMITTED_ARGUMENT_COUNT || argCount > MAX_PERMITTED_ARGUMENT_COUNT) {
            usage();
            return;
        }

        rootNameServer = InetAddress.getByName(args[0]);
        DNSResponse.globalServer = InetAddress.getByName(args[0]);
        fqdn = args[1];
        DNSResponse.firstQueryAddress = args[1];

        if (argCount == 3) {  // option provided
            if (args[2].equals("-t")) {
                tracingOn = true;
                DNSResponse.tracingOn = true;
            } else if (args[2].equals("-6")) {
                IPV6Query = true;
            } else if (args[2].equals("-t6")) {
                tracingOn = true;
                IPV6Query = true;
                DNSResponse.tracingOn = true;
            } else { // option present but wasn't valid option
                usage();
                return;
            }
        }
        lookup(rootNameServer, fqdn, tracingOn, IPV6Query);
    }


    public static void lookup(InetAddress rootNameServer, String fqdn, boolean tracingOn, boolean IPV6Query) throws Exception {

        DNSResponse response;
        String typeOfSearch = "";

        // Start adding code here to initiate the lookup
        //HEADER
        //QUERY ID
        Random random = new Random();
        int randomInt = random.nextInt(65535);
        ByteBuffer b = ByteBuffer.allocate(2);
        b.putShort((short) randomInt);
        byte[] queryID = b.array();


        byte[] rest = new byte[]{
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };

        byte[] header = new byte[queryID.length + rest.length];
        System.arraycopy(queryID, 0, header, 0, queryID.length);
        System.arraycopy(rest, 0, header, queryID.length, rest.length);

        //QUESTION
        String[] parts = fqdn.split("\\.");
        int partsOfDom = parts.length;


        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (int i = 0; i < partsOfDom; i++) {
            outputStream.write((byte) parts[i].length());
            outputStream.write(parts[i].getBytes(StandardCharsets.UTF_8));
        }
        byte[] qName = outputStream.toByteArray();
        byte[] endByte = new byte[]{(byte) 0x00};
        byte[] qType = new byte[2];

        if (IPV6Query) {
            qType[0] = (byte) 0x00;
            qType[1] = (byte) 0x1C;
            typeOfSearch = "AAAA";
        } else {
            qType[0] = (byte) 0x00;
            qType[1] = (byte) 0x01;
            typeOfSearch = "A";
        }
        byte[] qClass = new byte[]{(byte) 0x00, (byte) 0x01};

        ByteArrayOutputStream ques = new ByteArrayOutputStream();

        ques.write(qName);
        ques.write(endByte);
        ques.write(qType);
        ques.write(qClass);

        byte[] question = ques.toByteArray();
        byte[] finalQuery = new byte[header.length + question.length];

        System.arraycopy(header, 0, finalQuery, 0, header.length);
        System.arraycopy(question, 0, finalQuery, header.length, question.length);

        DatagramPacket sendPacket = new DatagramPacket(finalQuery, finalQuery.length, rootNameServer, 53);

        while (noResult) {
            try {
                byte[] receiveData = new byte[1024];
                DatagramSocket clientSocket = new DatagramSocket();
                clientSocket.setSoTimeout(200);
                clientSocket.send(sendPacket);
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                clientSocket.receive(receivePacket);
                clientSocket.close();
                response = new DNSResponse(receiveData, receiveData.length, fqdn, rootNameServer, typeOfSearch, IPV6Query);
                response.dumpResponse();
            } catch (SocketTimeoutException e) {
                if (counterOfSending != 3) {
                    counterOfSending++;
                    continue;
                } else {
                    System.out.println(fqdn + " " + "-2" + "   " + "A " + "0.0.0.0");
                    return;
                }
            } catch (Exception e2) {
                System.out.println(fqdn + " " + "-4" + "   " + "A " + "0.0.0.0");
            }
            noResult = false;
        }
    }


    private static void usage() {
        System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-6|-t|t6]");
        System.out.println("   where");
        System.out.println("       rootDNS - the IP address (in dotted form) of the root");
        System.out.println("                 DNS server you are to start your search at");
        System.out.println("       name    - fully qualified domain name to lookup");
        System.out.println("       -6      - return an IPV6 address");
        System.out.println("       -t      - trace the queries made and responses received");
        System.out.println("       -t6     - trace the queries made, responses received and return an IPV6 address");
    }

    // Helper to see what I'm sending for a lookup
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}


