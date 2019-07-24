package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class MscngLib extends NativeECLibrary {

    public MscngLib() {
        super("mscng_provider", "bcrypt");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
