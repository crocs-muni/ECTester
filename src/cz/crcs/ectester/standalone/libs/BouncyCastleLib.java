package cz.crcs.ectester.standalone.libs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class BouncyCastleLib {

    public BouncyCastleLib() {

    }

    public boolean setUp() {
        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (NullPointerException | SecurityException ignored) {
            return false;
        }
        return true;
    }

}
