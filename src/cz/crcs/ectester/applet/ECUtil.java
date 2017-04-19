package cz.crcs.ectester.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECUtil {

    private static short nullCheck(Object obj, short sw) {
        if (obj == null)
            ISOException.throwIt(sw);
        return ISO7816.SW_NO_ERROR;
    }

    static short objCheck(Object obj) {
        return nullCheck(obj, ECTesterApplet.SW_OBJECT_NULL);
    }

    static short keypairCheck(KeyPair keyPair) {
        return nullCheck(keyPair, ECTesterApplet.SW_KEYPAIR_NULL);
    }

    static short kaCheck(KeyAgreement keyAgreement) {
        return nullCheck(keyAgreement, ECTesterApplet.SW_KA_NULL);
    }

    static short signCheck(Signature signature) {
        return nullCheck(signature, ECTesterApplet.SW_SIGNATURE_NULL);
    }
}
