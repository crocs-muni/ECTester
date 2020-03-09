package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Matěj Grabovský matej@mgrabovsky.net
 */
public class LibresslLib extends NativeECLibrary {
    public LibresslLib() {
        super("libressl_provider", "lib_libressl.so");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
