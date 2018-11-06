package cz.crcs.ectester.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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
        return nullCheck(obj, AppletBase.SW_OBJECT_NULL);
    }

    public static short keypairCheck(KeyPair keyPair) {
        return nullCheck(keyPair, AppletBase.SW_KEYPAIR_NULL);
    }

    public static short kaCheck(KeyAgreement keyAgreement) {
        return nullCheck(keyAgreement, AppletBase.SW_KA_NULL);
    }

    public static short signCheck(Signature signature) {
        return nullCheck(signature, AppletBase.SW_SIGNATURE_NULL);
    }
}
