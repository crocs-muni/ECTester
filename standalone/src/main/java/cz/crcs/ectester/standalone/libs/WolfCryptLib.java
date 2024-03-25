package cz.crcs.ectester.standalone.libs;

import com.wolfssl.provider.jce.WolfCryptProvider;

import java.util.HashSet;
import java.util.Set;

public class WolfCryptLib extends ProviderECLibrary {

    public WolfCryptLib() {
        super(new WolfCryptProvider());
    }

    @Override
    public Set<String> getCurves() {
        return new HashSet<>();
    }
}
