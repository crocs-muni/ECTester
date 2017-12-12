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
        super(new BouncyCastleProvider());
    }

    @Override
    public Set<String> getCurves() {
        Set<String> result = new TreeSet<>();
        Enumeration names = ECNamedCurveTable.getNames();
        while (names.hasMoreElements()) {
            result.add((String) names.nextElement());
        }
        return result;
    }
}
