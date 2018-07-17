
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;


// Lots of the action associated with handling a DNS query is processing
// the response. Although not required you might find the following skeleton of
// a DNSreponse helpful. The class below has bunch of instance data that typically needs to be 
// parsed from the response. If you decide to use this class keep in mind that it is just a 
// suggestion and feel free to add or delete methods to better suit your implementation as 
// well as instance variables.


public class DNSResponse {
    public static int counterOfQuery;// when it hits 30 it should fail and error code -3
    public static InetAddress globalServer;
    public static boolean hasPrintedResult = false;
    public String typeOfSearch = "";
    public static boolean hasHitNSIPV6 = false;
    public static String firstQueryAddress;
    private InetAddress rootNameServer;
    public static boolean tracingOn;
    public boolean IPV6Query;
    private int queryID;                  // this is for the response it must match the one in the request
    private int answerCount = 0;          // number of answers  
    private boolean decoded = false;      // Was this response successfully decoded
    private int nsCount = 0;              // number of nscount response records
    private int additionalCount = 0;      // number of additional (alternate) response records
    private boolean authoritative = false;// Is this an authoritative record
    private int bytePos = 0;              // keeps track on which byte we're at during parsing
    private String queryAddress;          // the server we are requesting
    private RR answer[];
    private RR altInfo[];
    private RR ns[];
    // Note you will almost certainly need some additional instance variables.

    // When in trace mode you probably want to dump out all the relevant information in a response

    void dumpResponse() throws Exception {

        if (counterOfQuery >= 30) {
            System.out.println(firstQueryAddress + " " + "-3" + "   " + "A " + "0.0.0.0");
        }
        if (tracingOn && counterOfQuery < 30) {
            System.out.println("\nQuery ID     " + queryID + " " + queryAddress + "  " + typeOfSearch + " --> " + rootNameServer.getHostAddress());
            System.out.println("Response ID: " + queryID + " Authoritative = " + authoritative);

            System.out.println("  Answers (" + answerCount + ")");
            for (int i = 0; i < answerCount; i++) {
                answer[i].printItem();
            }

            System.out.println("  Nameservers (" + nsCount + ")");
            for (int i = 0; i < nsCount; i++) {
                ns[i].printItem();
            }
            System.out.println("  Additional Information (" + additionalCount + ")");
            for (int i = 0; i < additionalCount; i++) {
                altInfo[i].printItem();
            }
        }

        if (answerCount != 0 && (answer[0].getType() == "A" | answer[0].getType() == "AAAA") && !answer[0].getRecordName().startsWith("ns")) {
            hasPrintedResult = true;
            for (int i = 0; i < answerCount; i++) {
                System.out.println(firstQueryAddress + " " + answer[i].getTTL() + "    " + answer[i].getType() + " " + answer[i].getIPAddress().getHostAddress());
            }
        }


        if (answerCount == 0 && nsCount == 1 && additionalCount == 0 && counterOfQuery < 30) {
            System.out.println(firstQueryAddress + " " + "-6" + "   " + "A " + "0.0.0.0");
        }

        InetAddress reQueryAddress = null;

        if (decoded && answerCount == 0 && additionalCount != 0 && counterOfQuery < 30) {
            for (int i = 0; i < additionalCount; i++) {
                if (altInfo[i].type == 1) { // checks for the first alt info is "A" (routable ipv4 address)
                    reQueryAddress = altInfo[i].getIPAddress();
                    break;
                }
            }
            DNSlookup.lookup(reQueryAddress, queryAddress, tracingOn, IPV6Query);
        }

        if (decoded && answerCount == 1 && nsCount == 0 && additionalCount == 0 && answer[0].type == 5 && counterOfQuery < 30) {
            DNSlookup.lookup(globalServer, answer[0].getCname(), tracingOn, IPV6Query);
        }

        if (decoded && answerCount == 0 && nsCount != 0 && ns[0].getCname() != null && additionalCount == 0 && counterOfQuery < 30) {
            if (IPV6Query)
                hasHitNSIPV6 = true;
            DNSlookup.lookup(globalServer, ns[0].getCname(), tracingOn, false);
        }

        if (decoded && answerCount != 0 && !hasPrintedResult && counterOfQuery < 30) {

            for (int i = 0; i < answerCount; i++) {
                if (answer[i].getRecordName().equals(queryAddress) && answer[i].getType().equals("A") && answer[i].getRecordName().startsWith("ns")) {
                    if (hasHitNSIPV6)
                        DNSlookup.lookup(answer[i].getIPAddress(), firstQueryAddress, tracingOn, true);
                    else
                        DNSlookup.lookup(answer[i].getIPAddress(), firstQueryAddress, tracingOn, IPV6Query);
                    break;
                }
                if (answer[i].getRecordName().equals(queryAddress) && answer[i].type == 5) {
                    DNSlookup.lookup(globalServer, answer[i].getCname(), tracingOn, IPV6Query);
                    break;
                }
            }
        }

    }

    // The constructor: you may want to add additional parameters, but the two shown are 
    // probably the minimum that you need.

    public DNSResponse(byte[] data, int len, String queryAddress, InetAddress rootNameServer, String typeOfSearch, boolean IPV6Query) {
        this.queryAddress = queryAddress;
        this.rootNameServer = rootNameServer;
        this.typeOfSearch = typeOfSearch;
        this.IPV6Query = IPV6Query;
        counterOfQuery++;
        extractData(data);
    }

    public void extractData(byte[] data) {
        // setting query, query address, and authoritative or not
        queryID = (data[bytePos++] << 8) & 0xff;
        queryID = queryID | (data[bytePos++] & 0xff);

        if ((data[bytePos++] & 0x4) != 0) {
            this.authoritative = true;
        }


        // this is the RCODE section (checks whether an error has occurred)
        if ((data[bytePos++] & 0x0f) == 0) {
            decoded = true;
        }

        bytePos += 2; // skipping over irrelevant data

        // ANSWER
        answerCount = (data[bytePos++] << 8) & 0xff00;
        answerCount = answerCount | (data[bytePos++] & 0xff);
        answer = new RR[answerCount];

        // NS
        nsCount = (data[bytePos++] << 8) & 0xff00;
        nsCount = nsCount | (data[bytePos++] & 0xff);
        ns = new RR[nsCount];

        // AR
        additionalCount = (data[bytePos++] << 8) & 0xff00;
        additionalCount = additionalCount | (data[bytePos++] & 0xff);
        altInfo = new RR[additionalCount];

        // DOMAIN SECTION
        bytePos += queryAddress.length() + 2;

        bytePos += 4; // skipping qtype and qclass

        // Time to get all the RR stuffs
        for (int i = 0; i < answerCount; i++) {
            answer[i] = getRR(data);
        }

        for (int i = 0; i < nsCount; i++) {
            ns[i] = getRR(data);
        }

        for (int i = 0; i < additionalCount; i++) {
            altInfo[i] = getRR(data);
        }


        // The following are probably some of the things
        // you will need to do.
        // Extract the query ID

        // Make sure the message is a query response and determine
        // if it is an authoritative response or note

        // determine answer count

        // determine NS Count

        // determine additional record count

        // Extract list of answers, name server, and additional information response
        // records
    }


    // You will probably want a methods to extract a compressed FQDN, IP address
    // cname, authoritative DNS servers and other values like the query ID etc.


    // You will also want methods to extract the response records and record
    // the important values they are returning. Note that an IPV6 reponse record
    // is of type 28. It probably wouldn't hurt to have a response record class to hold
    // these records.


    private String getFQDN(byte[] data) {
        String FQDN = "";
        boolean firstRun = true; // setting it to true first because assume at first runthrough it will be true
        for (int cnt = (data[bytePos++] & 0xff); cnt != 0; cnt = (data[bytePos++] & 0xff)) {
            if (!firstRun) {
                FQDN += ".";
            } else {
                firstRun = false;
            }

            if ((cnt & 0xC0) > 0) {
                cnt = (cnt & 0x3f) << 8;
                cnt = cnt | (data[bytePos++] & 0xff);
                FQDN = recurseFQDN(FQDN, data, cnt);
                break;
            } else {
                for (int i = 0; i < cnt; i++) {
                    FQDN += (char) data[bytePos++];
                }
            }
        }

        return FQDN;
    }


    private String recurseFQDN(String FQDN, byte[] data, int offset) {
        boolean firstRun = true;
        for (int cnt = (data[offset++] & 0xff); cnt != 0; cnt = (data[offset++] & 0xff)) {
            if (!firstRun) {
                FQDN += '.';
            } else {
                firstRun = false;
            }

            if ((cnt & 0xC0) > 0) {
                cnt = (cnt & 0x3f) << 8;
                cnt = cnt | (data[offset++] & 0xff);
                FQDN = recurseFQDN(FQDN, data, cnt);
                break;
            } else {

                for (int i = 0; i < cnt; i++) {
                    FQDN = FQDN + (char) data[offset++];
                }
            }
        }

        return FQDN;
    }

    private RR getRR(byte[] data) {
        String FQDN = getFQDN(data);


        // 2 bytes of type
        int t = (data[bytePos++] << 8 & 0xffff);
        t = t | (data[bytePos++] & 0xff);

        // 2 bytes of class
        int rclass = (data[bytePos++] << 8 & 0xffff);
        rclass = rclass | (data[bytePos++] & 0xff);

        // 4 bytes of TTL
        int ttl = 0;
        for (int i = 0; i < 4; i++) {
            ttl = ttl << 8;
            ttl = ttl | (data[bytePos++] & 0xff);
        }

        // Rest of data (length dynamic depending on what it is)

        int rest = (data[bytePos++] << 8 & 0xffff);
        rest = rest | (data[bytePos++] & 0xff);

        RR recordResponse = null;
        InetAddress recordIP = null;

        if (rclass == 1) {
            if (t == 1) { // ipv4
                byte ipV4Addr[] = new byte[4];
                for (int i = 0; i < 4; i++) {
                    ipV4Addr[i] = data[bytePos + i];
                }
                try {
                    recordIP = InetAddress.getByAddress(ipV4Addr);
                } catch (Exception e) {
                    System.out.println("Error resolving host");
                }
                recordResponse = new ipV4AddressRR(FQDN, t, rclass, ttl, recordIP);
            } else if (t == 5) { // cname
                String cname = "";
                cname = recurseFQDN(cname, data, bytePos);
                recordResponse = new cnameRR(FQDN, t, rclass, ttl, cname);
            } else if (t == 2) { // ns
                String cname = "";
                cname = recurseFQDN(cname, data, bytePos);
                recordResponse = new nameServerRR(FQDN, t, rclass, ttl, cname);

            } else if (t == 28) { // ipv6
                // should be 16 bytes according to ass2 notes
                byte ipv6addr[] = new byte[16];
                for (int i = 0; i < 16; i++) {
                    ipv6addr[i] = data[bytePos + i];
                }

                try {
                    recordIP = InetAddress.getByAddress(ipv6addr);
                } catch (Exception e) {
                    System.out.println("Error resolving to host");
                }
                recordResponse = new ipV6AddressRR(FQDN, t, rclass, ttl, recordIP);
            } else {
                recordResponse = new RR(FQDN, t, rclass, ttl);
            }

        } else {
            recordResponse = new RR(FQDN, t, rclass, ttl);
        }

        bytePos += rest;
        return recordResponse;

    }

    private class RR {
        private String recordName;
        private int type;
        private int rclass;
        private int ttl;
        private InetAddress addr = null;
        private String cname = null;
        private String typeInString = "";

        // constructor
        RR(String n, int t, int r, int tt) {
            recordName = n;
            type = t;
            rclass = r;
            ttl = tt;
        }

        void printItemsInOrder(String recordType, String recordValue) {
            // found in ass2 description
            System.out.format("       %-30s %-10d %-4s %s\n", recordName, ttl, recordType, recordValue);
        }

        // this will be the method that will be called for each class item
        void printItem() {
            printItemsInOrder(Integer.toString(type), "----");
        }

        InetAddress getIPAddress() {
            return addr;
        }

        String getRecordName() {
            return recordName;
        }

        String getCname() {
            return cname;
        }

        int getTTL() {
            return ttl;
        }

        String getType() {
            return typeInString;
        }
    }


    private class nameServerRR extends RR {
        String serverName;

        nameServerRR(String n, int t, int r, int tt, String serverName) {
            super(n, t, r, tt);
            this.serverName = serverName;
        }

        String getCname() {
            return serverName;
        }

        void printItem() {
            printItemsInOrder("NS", serverName);
        }
    }


    private class cnameRR extends RR {
        String cname;

        cnameRR(String n, int t, int r, int tt, String cname) {
            super(n, t, r, tt);
            this.cname = cname;
        }

        String getCname() {
            return cname;
        }

        void printItem() {
            printItemsInOrder("CN", cname);
        }
    }


    private class ipV4AddressRR extends RR {
        InetAddress addr;

        ipV4AddressRR(String n, int t, int r, int tt, InetAddress addr) {
            super(n, t, r, tt);
            this.addr = addr;
        }

        InetAddress getIPAddress() {
            return addr;
        }

        String getType() {
            return "A";
        }

        void printItem() {
            printItemsInOrder("A", addr.getHostAddress());
        }
    }


    private class ipV6AddressRR extends RR {
        InetAddress addr;

        ipV6AddressRR(String n, int t, int r, int tt, InetAddress addr) {
            super(n, t, r, tt);
            this.addr = addr;
        }

        InetAddress getIPAddress() {
            return addr;
        }

        String getType() {
            return "AAAA";
        }

        void printItem() {
            printItemsInOrder("AAAA", addr.getHostAddress());
        }
    }


}


