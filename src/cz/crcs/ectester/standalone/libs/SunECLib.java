package cz.crcs.ectester.standalone.libs;

import sun.security.ec.SunEC;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SunECLib extends ProviderECLibrary {

    public SunECLib() {
        super(new SunEC());
    }

}
