package cz.crcs.ectester.reader;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.util.List;
import java.util.Scanner;
import javacard.framework.AID;

import javax.smartcardio.*;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardMngr {
    private CardTerminal terminal = null;
    private CardChannel channel = null;
    private Card card = null;
    
    // Simulator related attributes
    private CAD cad = null;
    private JavaxSmartCardInterface simulator = null;

    private boolean simulate = false;
    
    private final byte selectCM[] = {
        (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x07, (byte) 0xa0, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x18, (byte) 0x43, (byte) 0x4d};

    public static final byte OFFSET_CLA = 0x00;
    public static final byte OFFSET_INS = 0x01;
    public static final byte OFFSET_P1 = 0x02;
    public static final byte OFFSET_P2 = 0x03;
    public static final byte OFFSET_LC = 0x04;
    public static final byte OFFSET_DATA = 0x05;
    public static final byte HEADER_LENGTH = 0x05;

    public static final short DATA_RECORD_LENGTH = (short) 0x80; // 128B per record
    public static final short NUMBER_OF_RECORDS = (short) 0x0a; // 10 records

    public CardMngr() {
        this(false);
    }

    public CardMngr(boolean simulate)  {
        this.simulate = simulate;
    }

    public boolean connectToCard() throws CardException {
        if (simulate)
            return true;

        // TRY ALL READERS, FIND FIRST SELECTABLE
        List<CardTerminal> terminalList = getReaderList();

        if (terminalList == null || terminalList.isEmpty()) {
            System.out.println("No terminals found");
            return false;
        }

        //List numbers of Card readers
        boolean cardFound = false;
        for (int i = 0; i < terminalList.size(); i++) {
            System.out.println(i + " : " + terminalList.get(i));
            terminal = terminalList.get(i);
            if (terminal.isCardPresent()) {
                card = terminal.connect("*");
                System.out.println("card: " + card);
                channel = card.getBasicChannel();

                //reset the card
                System.out.println(Util.bytesToHex(card.getATR().getBytes()));
                
                cardFound = true;
            }
        }

        return cardFound;
    }
    
    public boolean connectToCardSelect() throws CardException {
        if (simulate)
            return true;

        // Test available card - if more present, let user to select one
        List<CardTerminal> terminalList = CardMngr.getReaderList();
        if (terminalList == null || terminalList.isEmpty()) {
            System.out.println("ERROR: No suitable reader with card detected. Please check your reader connection");
            return false;
        } else {
            if (terminalList.size() == 1) {
                terminal = terminalList.get(0); // return first and only reader
            } else {
                int terminalIndex = 1;
                // Let user select target terminal
                for (CardTerminal terminal : terminalList) {
                    Card card;
                    try {
                        card = terminal.connect("*");
                        ATR atr = card.getATR();
                        System.out.println(terminalIndex + " : " + terminal.getName() + " - " + Util.bytesToHex(atr.getBytes()));
                        terminalIndex++;
                    } catch (CardException ex) {
                        ex.printStackTrace(System.out);
                    }
                }
                System.out.print("Select index of target reader you like to use 1.." + (terminalIndex - 1) + ": ");
                Scanner sc = new Scanner(System.in);
                int answ = sc.nextInt();
                System.out.println(String.format("%d", answ));
                answ--; // is starting with 0 
                // BUGBUG; verify allowed index range
                terminal = terminalList.get(answ);
            }
        }
        
        if (terminal != null) {
            card = terminal.connect("*");
            System.out.println("card: " + card);
            channel = card.getBasicChannel();
        }

        return true;
    }

    public boolean reconnectToCard(byte[] selectAPDU) throws CardException {
        if (simulate)
            return true;

        if (connected()) {
            disconnectFromCard();
        }

        boolean result = connectToCard();
        if (result) {
            // Select our application on card
            send(selectAPDU);
        }
        return result;
    }

    public boolean connected() {
        return simulate || card != null;
    }

    public void disconnectFromCard() throws CardException {
        if (simulate)
            return;

        if (card != null) {
            card.disconnect(false);
            card = null;
        }
    }

    public byte[] getCPLCData() throws Exception {
        byte[] data;

        // TODO: Modify to obtain CPLC data
        byte apdu[] = new byte[HEADER_LENGTH];
        apdu[OFFSET_CLA] = (byte) 0x00;
        apdu[OFFSET_INS] = (byte) 0x00;
        apdu[OFFSET_P1] = (byte) 0x00;
        apdu[OFFSET_P2] = (byte) 0x00;
        apdu[OFFSET_LC] = (byte) 0x00;

        ResponseAPDU resp = send(apdu);
        if (resp.getSW() != 0x9000) { // 0x9000 is "OK"
            System.out.println("Fail to obtain card's response data");
            data = null;
        } else {
            byte temp[] = resp.getBytes();
            data = new byte[temp.length - 2];
            System.arraycopy(temp, 0, data, 0, temp.length - 2);
            // Last two bytes are status word (also obtainable by resp.getSW())
            // Take a look at ISO7816_status_words.txt for common codes
        }

        return data;
    }

    public void probeCardCommands() throws Exception {
        // TODO: modify to probe for instruction
        for (int i = 0; i <= 0; i++) {
            byte apdu[] = new byte[HEADER_LENGTH];
            apdu[OFFSET_CLA] = (byte) 0x00;
            apdu[OFFSET_INS] = (byte) 0x00;
            apdu[OFFSET_P1] = (byte) 0x00;
            apdu[OFFSET_P2] = (byte) 0x00;
            apdu[OFFSET_LC] = (byte) 0x00;

            ResponseAPDU resp = send(apdu);
            
            System.out.println("Response: " + Integer.toHexString(resp.getSW()));  
            
            if (resp.getSW() != 0x6D00) { // Note: 0x6D00 is SW_INS_NOT_SUPPORTED
                // something?
            }
        }
    }
    
    public static List<CardTerminal> getReaderList() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            return factory.terminals().list();
        } catch (CardException ex) {
            System.out.println("Exception : " + ex);
            return null;
        }
    }

    public ResponseAPDU sendAPDU(CommandAPDU apdu) throws CardException {
        System.out.println(">>>>");
        System.out.println(apdu);

        System.out.println(Util.bytesToHex(apdu.getBytes()));

        long elapsed = -System.nanoTime();

        ResponseAPDU responseAPDU = channel.transmit(apdu);

        elapsed += System.nanoTime();

        System.out.println(responseAPDU);
        System.out.println(Util.bytesToHex(responseAPDU.getBytes()));

        if (responseAPDU.getSW1() == (byte) 0x61) {
            CommandAPDU apduToSend = new CommandAPDU((byte) 0x00,
                    (byte) 0xC0, (byte) 0x00, (byte) 0x00,
                    responseAPDU.getSW1());

            responseAPDU = channel.transmit(apduToSend);
            System.out.println(Util.bytesToHex(responseAPDU.getBytes()));
        }

        System.out.println("<<<<");
        System.out.println("Elapsed time (ms): " + elapsed / 1000000);
        return responseAPDU;
    }

    public ResponseAPDU sendAPDU(byte apdu[]) throws CardException {
        CommandAPDU commandAPDU = new CommandAPDU(apdu);
        return sendAPDU(commandAPDU);
    }
    
    public boolean prepareLocalSimulatorApplet(byte[] appletAIDArray, byte[] installData, Class appletClass) {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        cad = new CAD(System.getProperties());
        simulator = (JavaxSmartCardInterface) cad.getCardInterface();
        AID appletAID = new AID(appletAIDArray, (short) 0, (byte) appletAIDArray.length);

        AID appletAIDRes =  simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        return simulator.selectApplet(appletAID);
    }

    public ResponseAPDU sendAPDUSimulator(CommandAPDU apdu) {
        System.out.println(">>>>");
        System.out.println(Util.bytesToHex(apdu.getBytes()));

        ResponseAPDU response = simulator.transmitCommand(apdu);
        byte[] responseBytes = response.getBytes();

        System.out.println(Util.bytesToHex(responseBytes));
        System.out.println("<<<<");

        return response;
    }

    public ResponseAPDU sendAPDUSimulator(byte[] apdu) {
        CommandAPDU commandAPDU = new CommandAPDU(apdu);
        return sendAPDUSimulator(commandAPDU);
    }

    public ResponseAPDU send(CommandAPDU apdu) throws CardException {
        ResponseAPDU response;
        if (simulate) {
            response = sendAPDUSimulator(apdu);
        } else {
            response = sendAPDU(apdu);
        }
        return response;
    }

    public ResponseAPDU send(byte[] apdu) throws CardException {
        CommandAPDU commandAPDU = new CommandAPDU(apdu);
        return send(commandAPDU);
    }

    public ResponseAPDU[] send(CommandAPDU... apdus) throws CardException {
        ResponseAPDU[] result = new ResponseAPDU[apdus.length];
        for (int i = 0; i < apdus.length; i++) {
            result[i] = send(apdus[i]);
        }
        return result;
    }

}
