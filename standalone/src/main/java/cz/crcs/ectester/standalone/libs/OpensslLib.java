package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class OpensslLib extends NativeECLibrary {
    public OpensslLib() {
        super("OpenSSL", "openssl_provider");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
