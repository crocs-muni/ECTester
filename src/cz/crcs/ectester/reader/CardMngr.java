package cz.crcs.ectester.reader;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import cz.crcs.ectester.common.util.ByteUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;

import javax.smartcardio.*;
import java.util.*;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardMngr {
    private CardTerminal terminal = null;
    private CardChannel channel = null;
    private Card card = null;

    // Simulator related attributes
    private JavaxSmartCardInterface simulator = null;

    private boolean simulate = false;
    private boolean verbose = true;
    private boolean chunking = false;

    private final byte[] selectCM = {
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
    }

    public CardMngr(boolean verbose) {
        this.verbose = verbose;
    }

    public CardMngr(boolean verbose, boolean simulate) {
        this(verbose);
        this.simulate = simulate;
    }

    private void connectWithHighest() throws CardException {
        try {
            card = terminal.connect("T=1");
        } catch (CardException ex) {
            if (verbose)
                System.out.println("T=1 failed, trying protocol '*'");
            card = terminal.connect("*");
            if (card.getProtocol().equals("T=0")) {
                chunking = true;
            }
        }
    }

    public boolean connectToCard() throws CardException {
        if (simulate)
            return true;

        // TRY ALL READERS, FIND FIRST SELECTABLE
        List<CardTerminal> terminalList = getReaderList();

        if (terminalList == null || terminalList.isEmpty()) {
            System.err.println("No terminals found");
            return false;
        }

        //List numbers of Card readers
        boolean cardFound = false;
        for (int i = 0; i < terminalList.size(); i++) {

            if (verbose)
                System.out.println(i + " : " + terminalList.get(i));

            terminal = terminalList.get(i);
            if (terminal.isCardPresent()) {
                connectWithHighest();

                if (verbose)
                    System.out.println("card: " + card);
                channel = card.getBasicChannel();

                //reset the card
                if (verbose)
                    System.out.println(ByteUtil.bytesToHex(card.getATR().getBytes()));

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
            System.err.println("ERROR: No suitable reader with card detected. Please check your reader connection");
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
                        System.out.println(terminalIndex + " : " + terminal.getName() + " - " + ByteUtil.bytesToHex(atr.getBytes()));
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
            connectWithHighest();
            if (verbose)
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

    public void setChunking(boolean state) {
        chunking = state;
    }

    public String getProtocol() {
        if (simulate) {
            return simulator.getProtocol();
        } else {
            if (card != null) {
                return card.getProtocol();
            } else {
                return null;
            }
        }
    }

    // Functions for CPLC taken and modified from https://github.com/martinpaljak/GlobalPlatformPro
    private static final byte CLA_GP = (byte) 0x80;
    private static final byte ISO7816_INS_GET_DATA = (byte) 0xCA;
    private static final byte[] FETCH_GP_CPLC_APDU = {CLA_GP, ISO7816_INS_GET_DATA, (byte) 0x9F, (byte) 0x7F, (byte) 0x00};
    private static final byte[] FETCH_ISO_CPLC_APDU = {ISO7816.CLA_ISO7816, ISO7816_INS_GET_DATA, (byte) 0x9F, (byte) 0x7F, (byte) 0x00};
    private static final byte[] FETCH_GP_CARDDATA_APDU = {CLA_GP, ISO7816_INS_GET_DATA, (byte) 0x00, (byte) 0x66, (byte) 0x00};

    public byte[] fetchCPLC() throws CardException {
        // Try CPLC via GP
        ResponseAPDU resp = send(FETCH_GP_CPLC_APDU);
        // If GP CLA fails, try with ISO
        if (resp.getSW() == (ISO7816.SW_CLA_NOT_SUPPORTED & 0xffff)) {
            resp = send(FETCH_ISO_CPLC_APDU);
        }
        if (resp.getSW() == (ISO7816.SW_NO_ERROR & 0xffff)) {
            return resp.getData();
        }
        return null;
    }

    public static final class CPLC {
        public enum Field {
            ICFabricator,
            ICType,
            OperatingSystemID,
            OperatingSystemReleaseDate,
            OperatingSystemReleaseLevel,
            ICFabricationDate,
            ICSerialNumber,
            ICBatchIdentifier,
            ICModuleFabricator,
            ICModulePackagingDate,
            ICCManufacturer,
            ICEmbeddingDate,
            ICPrePersonalizer,
            ICPrePersonalizationEquipmentDate,
            ICPrePersonalizationEquipmentID,
            ICPersonalizer,
            ICPersonalizationDate,
            ICPersonalizationEquipmentID
        }

        private Map<Field, byte[]> values = new TreeMap<>();

        public CPLC(byte[] data) {
            if (data == null) {
                return;
            }
            if (data.length < 3 || data[2] != 0x2A) {
                throw new IllegalArgumentException("CPLC must be 0x2A bytes long");
            }
            //offset = TLVUtils.skipTag(data, offset, (short)0x9F7F);
            short offset = 3;
            values.put(Field.ICFabricator, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICType, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.OperatingSystemID, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.OperatingSystemReleaseDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.OperatingSystemReleaseLevel, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICFabricationDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICSerialNumber, Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;
            values.put(Field.ICBatchIdentifier, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICModuleFabricator, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICModulePackagingDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICCManufacturer, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICEmbeddingDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPrePersonalizer, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPrePersonalizationEquipmentDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPrePersonalizationEquipmentID, Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;
            values.put(Field.ICPersonalizer, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPersonalizationDate, Arrays.copyOfRange(data, offset, offset + 2));
            offset += 2;
            values.put(Field.ICPersonalizationEquipmentID, Arrays.copyOfRange(data, offset, offset + 4));
            offset += 4;
        }

        public Map<Field, byte[]> values() {
            return values;
        }
    }

    public ATR getATR() {
        if (simulate) {
            return new ATR(simulator.getATR());
        } else {
            if (card != null) {
                return card.getATR();
            } else {
                return null;
            }
        }
    }

    public CPLC getCPLC() throws CardException {
        byte[] data = fetchCPLC();
        return new CPLC(data);
    }

    public static String mapCPLCField(CPLC.Field field, byte[] value) {
        switch (field) {
            case ICFabricator:
                String id = ByteUtil.bytesToHex(value, false);
                String fabricatorName = "unknown";
                if (id.equals("3060")) {
                    fabricatorName = "Renesas";
                }
                if (id.equals("4090")) {
                    fabricatorName = "Infineon";
                }
                if (id.equals("4180")) {
                    fabricatorName = "Atmel";
                }
                if (id.equals("4250")) {
                    fabricatorName = "Samsung";
                }
                if (id.equals("4790")) {
                    fabricatorName = "NXP";
                }
                return id + " (" + fabricatorName + ")";
            default:
                return ByteUtil.bytesToHex(value, false);
        }
    }


    public static List<CardTerminal> getReaderList() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            return factory.terminals().list();
        } catch (CardException ex) {
            System.err.println("Exception : " + ex);
            return null;
        }
    }

    private CommandAPDU chunk(CommandAPDU apdu) throws CardException {
        if (verbose) {
            System.out.print("Chunking:");
        }
        byte[] data = apdu.getBytes();
        int numChunks = (data.length + 254) / 255;
        for (int i = 0; i < numChunks; ++i) {
            int chunkStart = i * 255;
            int chunkLength = 255;
            if (chunkStart + chunkLength > data.length) {
                chunkLength = data.length - chunkStart;
            }
            if (verbose) {
                System.out.print(" " + chunkLength);
            }
            byte[] chunk = new byte[chunkLength];
            System.arraycopy(data, chunkStart, chunk, 0, chunkLength);
            CommandAPDU cmd = new CommandAPDU(apdu.getCLA(), 0x7a, 0, 0, chunk);
            ResponseAPDU resp;
            if (simulate) {
                resp = simulator.transmitCommand(cmd);
            } else {
                resp = channel.transmit(cmd);
            }
            if ((short) resp.getSW() != ISO7816.SW_NO_ERROR) {
                throw new CardException("Chunking failed!");
            }
        }
        if (verbose)
            System.out.println();
        return new CommandAPDU(apdu.getCLA(), 0x7b, 0, 0, 0xff);
    }

    public ResponseAPDU sendAPDU(CommandAPDU apdu) throws CardException {
        if (verbose) {
            System.out.println(">>>>");
            System.out.println(apdu);

            System.out.println(ByteUtil.bytesToHex(apdu.getBytes()));
        }

        long elapsed;
        if (chunking && apdu.getNc() >= 0xff) {
            apdu = chunk(apdu);
        }

        elapsed = -System.nanoTime();

        ResponseAPDU responseAPDU = channel.transmit(apdu);

        elapsed += System.nanoTime();

        if (verbose) {
            System.out.println(responseAPDU);
            System.out.println(ByteUtil.bytesToHex(responseAPDU.getBytes()));
        }

        if (responseAPDU.getSW1() == (byte) 0x61) {
            CommandAPDU apduToSend = new CommandAPDU((byte) 0x00,
                    (byte) 0xC0, (byte) 0x00, (byte) 0x00,
                    responseAPDU.getSW2());

            responseAPDU = channel.transmit(apduToSend);
            if (verbose)
                System.out.println(ByteUtil.bytesToHex(responseAPDU.getBytes()));
        }

        if (verbose) {
            System.out.println("<<<<");
            System.out.println("Elapsed time (ms): " + elapsed / 1000000);
            System.out.println("---------------------------------------------------------");
        }
        return responseAPDU;
    }

    public ResponseAPDU sendAPDU(byte[] apdu) throws CardException {
        CommandAPDU commandAPDU = new CommandAPDU(apdu);
        return sendAPDU(commandAPDU);
    }

    public boolean prepareLocalSimulatorApplet(byte[] appletAIDArray, byte[] installData, Class<? extends Applet> appletClass) {
        simulator = new JavaxSmartCardInterface();
        AID appletAID = new AID(appletAIDArray, (short) 0, (byte) appletAIDArray.length);

        simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        return simulator.selectApplet(appletAID);
    }

    public ResponseAPDU sendAPDUSimulator(CommandAPDU apdu) throws CardException {
        if (verbose) {
            System.out.println(">>>>");
            System.out.println(apdu);
            System.out.println(ByteUtil.bytesToHex(apdu.getBytes()));
        }

        if (chunking && apdu.getNc() >= 0xff) {
            apdu = chunk(apdu);
        }

        ResponseAPDU response = simulator.transmitCommand(apdu);
        byte[] responseBytes = response.getBytes();

        if (verbose) {
            System.out.println(response);
            System.out.println(ByteUtil.bytesToHex(responseBytes));
            System.out.println("<<<<");
        }

        return response;
    }

    public ResponseAPDU sendAPDUSimulator(byte[] apdu) throws CardException {
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
}
