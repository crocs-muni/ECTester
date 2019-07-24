package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class BoringsslLib extends NativeECLibrary {
    public BoringsslLib() {
        super("boringssl_provider", "lib_boringssl.so");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
