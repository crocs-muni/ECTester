package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Matěj Grabovský matej@mgrabovsky.net
 */
public class LibresslLib extends NativeECLibrary {
    public LibresslLib() {
        super("LibreSSL", "libressl_provider");
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
