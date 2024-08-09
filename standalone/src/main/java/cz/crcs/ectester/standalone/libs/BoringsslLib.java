package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class BoringsslLib extends NativeECLibrary {
    public BoringsslLib() {
        super("BoringSSL", "boringssl_provider", "lib_boringssl.so");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();

    @Override
    public boolean supportsDeterministicPRNG() {
        // This is provided by the native preload that hooks all randomness sources.
        return true;
    }
}
