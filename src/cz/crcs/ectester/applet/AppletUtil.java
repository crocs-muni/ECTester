package cz.crcs.ectester.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class AppletUtil {

    private static short nullCheck(Object obj, short sw) {
        if (obj == null)
            ISOException.throwIt(sw);
        return ISO7816.SW_NO_ERROR;
    }

    public static short objCheck(Object obj) {
        return nullCheck(obj, ECTesterApplet.SW_OBJECT_NULL);
    }

    public static short keypairCheck(KeyPair keyPair) {
        return nullCheck(keyPair, ECTesterApplet.SW_KEYPAIR_NULL);
    }

    public static short kaCheck(KeyAgreement keyAgreement) {
        return nullCheck(keyAgreement, ECTesterApplet.SW_KA_NULL);
    }

    public static short signCheck(Signature signature) {
        return nullCheck(signature, ECTesterApplet.SW_SIGNATURE_NULL);
    }

    public static short readAPDU(APDU apdu, byte[] buffer, short length) {
        short read = apdu.setIncomingAndReceive();
        read += apdu.getOffsetCdata();
        short total = apdu.getIncomingLength();
        if (total > length) {
            return 0;
        }
        byte[] apduBuffer = apdu.getBuffer();

        short sum = 0;

        do {
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buffer, sum, read);
            sum += read;
            read = apdu.receiveBytes((short) 0);
        } while (sum < total);
        // TODO figure this out, in buffer + out buffer(apdubuf) or just send each param on its own?
        return 0;
    }
}
