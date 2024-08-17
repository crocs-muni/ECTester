package cz.crcs.ectester.standalone.libs;

import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;

import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Set;

/**
 * @author Michal Cech 445431@mail.muni.cz
 */
public class NettleLib extends NativeECLibrary {

    public NettleLib() {
        super("Nettle", "nettle_provider");
    }

    @Override
    native Provider createProvider();

    @Override
    public native Set<String> getCurves();

    public static ECGenParameterSpec parametersKnown(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params instanceof ECGenParameterSpec) {
            if (Arrays.asList("secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1").contains(((ECGenParameterSpec) params).getName())) {
                return (ECGenParameterSpec) params;
            }
        } else if (params instanceof ECParameterSpec) {
            ECParameterSpec spec = (ECParameterSpec) params;
            EC_Store store = EC_Store.getInstance();
            if (ECUtil.equalECParameterSpec(spec, store.getObject(EC_Curve.class, "secg/secp192r1").toSpec())) {
                return new ECGenParameterSpec("secp192r1");
            } else if (ECUtil.equalECParameterSpec(spec, store.getObject(EC_Curve.class, "secg/secp224r1").toSpec())) {
                return new ECGenParameterSpec("secp224r1");
            } else if (ECUtil.equalECParameterSpec(spec, store.getObject(EC_Curve.class, "secg/secp256r1").toSpec())) {
                return new ECGenParameterSpec("secp256r1");
            } else if (ECUtil.equalECParameterSpec(spec, store.getObject(EC_Curve.class, "secg/secp384r1").toSpec())) {
                return new ECGenParameterSpec("secp384r1");
            } else if (ECUtil.equalECParameterSpec(spec, store.getObject(EC_Curve.class, "secg/secp521r1").toSpec())) {
                return new ECGenParameterSpec("secp521r1");
            }
        }
        throw new InvalidAlgorithmParameterException("Unknown curve.");
    }

    @Override
    public native boolean supportsDeterministicPRNG();

    @Override
    public native boolean setupDeterministicPRNG(byte[] seed);
}
