package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Michal Cech 445431@mail.muni.cz
 */
public class NettleLib extends NativeECLibrary {

    public NettleLib() {
        super("nettle_provider", "nettle","hogweed", "gmp");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
