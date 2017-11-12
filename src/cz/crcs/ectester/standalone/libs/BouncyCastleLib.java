package cz.crcs.ectester.standalone.libs;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class BouncyCastleLib extends JavaECLibrary {

    public BouncyCastleLib() {
        super(new BouncyCastleProvider());
    }

}
