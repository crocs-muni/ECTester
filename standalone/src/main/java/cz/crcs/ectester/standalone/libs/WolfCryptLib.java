package cz.crcs.ectester.standalone.libs;

import com.wolfssl.provider.jce.WolfCryptProvider;

import java.util.HashSet;
import java.util.Set;

public class WolfCryptLib extends ProviderECLibrary {

    public WolfCryptLib() {
        super(new WolfCryptProvider());
    }

    @Override
    public boolean initialize() {
        try {
            System.loadLibrary("wolfcryptjni");
            return super.initialize();
        } catch (UnsatisfiedLinkError ule) {
            return false;
        }
    }

    @Override
    public Set<String> getCurves() {
        return new HashSet<>();
    }
}
