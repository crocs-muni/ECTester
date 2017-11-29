package cz.crcs.ectester.standalone.libs;

import sun.security.ec.SunEC;

import java.util.Set;
import java.util.TreeSet;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SunECLib extends ProviderECLibrary {

    public SunECLib() {
        super(new SunEC());
    }

    @Override
    public Set<String> getCurves() {
        String curves = provider.get("AlgorithmParameters.EC SupportedCurves").toString();
        String[] split = curves.split("\\|");
        Set<String> result = new TreeSet<>();
        for (String curve : split) {
            String body = curve.split(",")[0].substring(1);
            result.add(body);
        }
        return result;
    }
}
