package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class GcryptLib extends NativeECLibrary {

    public GcryptLib() {
        super("gcrypt_provider", "gcrypt", "gpg-error");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
