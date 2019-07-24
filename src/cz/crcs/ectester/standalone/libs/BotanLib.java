package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class BotanLib extends NativeECLibrary {

    public BotanLib() {
        super("botan_provider", "botan-2");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();
}
