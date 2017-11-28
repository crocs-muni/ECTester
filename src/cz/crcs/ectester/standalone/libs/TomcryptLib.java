package cz.crcs.ectester.standalone.libs;

import java.security.Provider;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TomcryptLib extends NativeECLibrary {

    public TomcryptLib() {
        super("tomcrypt_provider", "tommath", "tomcrypt");
    }

    @Override
    native Provider createProvider();
}
