package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class BotanLib extends NativeECLibrary {

    public BotanLib() {
        super("Botan", "botan_provider");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();

    @Override
    public native boolean supportsDeterministicPRNG();

    @Override
    public native boolean setupDeterministicPRNG(byte[] seed);
}
