package simpleapdu;

import applets.SimpleECCApplet;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author xsvenda
 */
public class SimpleAPDU {
    static CardMngr cardManager = new CardMngr();

    private static byte DEFAULT_USER_PIN[] = {(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30};
    private static byte NEW_USER_PIN[] = {(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    private static byte SELECT_SIMPLEAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    private final byte selectCM[] = {
        (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x07, (byte) 0xa0, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x18, (byte) 0x43, (byte) 0x4d};
    
    private static byte GENERATEKEY[] = {(byte) 0xB0, (byte) 0x5A, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00};
    private static byte RESPONDDATA[] = {(byte) 0xB0, (byte) 0x5B, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x30};
    public static void main(String[] args) {
        try {
            //
            // SIMULATED CARDS
            //
/*            
            // Prepare simulated card 
            byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial keys etc.
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, SimpleECCApplet.class);      
            
            // TODO: prepare proper APDU command
            short additionalDataLen = 0;
            byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apdu[CardMngr.OFFSET_INS] = (byte) 0x5a;
            apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
            apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            
            // TODO: if additional data are supplied (additionalDataLen != 0), then set proper inpupt here
            
            // NOTE: we are using sendAPDUSimulator() instead of sendAPDU()
            byte[] response = cardManager.sendAPDUSimulator(apdu); 
            // TODO: parse response data - status, data
            response = cardManager.sendAPDUSimulator(apdu);
            
*/                
            
            
            //
            // REAL CARDS
            //
            
            // TODO: Try same with real card
            if (cardManager.ConnectToCard()) {
                // Select our application on card
                cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                
                for (int i = 0; i < 10; i++) {
                    cardManager.sendAPDU(GENERATEKEY);
                }
                cardManager.sendAPDU(RESPONDDATA);
                
                cardManager.DisconnectFromCard();
            } else {
                System.out.println("Failed to connect to card");
            }
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}
