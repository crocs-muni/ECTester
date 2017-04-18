package cz.crcs.ectester.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyPair;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECUtil {

    static short nullCheck(KeyPair keyPair) {
        if (keyPair == null)
            ISOException.throwIt(ECTesterApplet.SW_KEYPAIR_NULL);
        return ISO7816.SW_NO_ERROR;
    }
}
