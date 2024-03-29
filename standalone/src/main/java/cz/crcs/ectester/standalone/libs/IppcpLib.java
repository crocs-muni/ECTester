package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class IppcpLib extends NativeECLibrary {

    public IppcpLib() {
        super("IPPCP", "ippcp_provider", "lib_ippcp.so");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
