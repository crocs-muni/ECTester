package cz.crcs.ectester.standalone.libs;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.Enumeration;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class BouncyCastleLib extends ProviderECLibrary {

    public BouncyCastleLib() {
        super("BouncyCastle", new BouncyCastleProvider());
    }

    @Override
    public Set<String> getCurves() {
        Set<String> result = new TreeSet<>();
        Enumeration<?> names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements()) {
            result.add((String) names.nextElement());
        }
        return result;
    }

    @Override
    public boolean supportsDeterministicPRNG() {
        return true;
    }

    @Override
    public boolean setupDeterministicPRNG(byte[] seed) {
        // This is done by passing the SecureRandom into the individual KeyPairGenerator, KeyAgreement and Signature
        // instances. Thus, this does nothing.
        return true;
    }
}
