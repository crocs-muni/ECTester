package cz.crcs.ectester.standalone.libs;

import java.security.Provider;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CryptoppLib extends NativeECLibrary {

    public CryptoppLib() {
        super("Crypto++","cryptopp_provider");
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
