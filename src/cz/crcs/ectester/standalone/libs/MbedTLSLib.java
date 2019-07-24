package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class MbedTLSLib extends NativeECLibrary {

    public MbedTLSLib() {
        super("mbedtls_provider", "mbedcrypto");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
