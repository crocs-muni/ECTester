package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTester;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.ec.EC_Curve;
import cz.crcs.ectester.reader.ec.EC_Key;
import cz.crcs.ectester.reader.output.OutputWriter;
import javacard.security.KeyPair;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class InvalidCurvesSuite extends TestSuite {

    public InvalidCurvesSuite(EC_Store dataStore, ECTester.Config cfg, OutputWriter writer) {
        super(dataStore, cfg, writer, "invalid");
    }

    @Override
    public List<Test> run(CardMngr cardManager) throws CardException, IOException {
        /* Set original curves (secg/nist/brainpool). Generate local.
         * Try ECDH with invalid public keys of increasing (or decreasing) order.
         */
        Map<String, EC_Key.Public> pubkeys = dataStore.getObjects(EC_Key.Public.class, "invalid");
        Map<EC_Curve, List<EC_Key.Public>> curves = new HashMap<>();
        for (EC_Key.Public key : pubkeys.values()) {
            EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
            if (cfg.namedCurve != null && !(key.getCurve().startsWith(cfg.namedCurve) || key.getCurve().equals(cfg.namedCurve))) {
                continue;
            }
            if (curve.getBits() != cfg.bits && !cfg.all) {
                continue;
            }
            if (curve.getField() == KeyPair.ALG_EC_FP && !cfg.primeField || curve.getField() == KeyPair.ALG_EC_F2M && !cfg.binaryField) {
                continue;
            }
            List<EC_Key.Public> keys = curves.getOrDefault(curve, new LinkedList<>());
            keys.add(key);
            curves.putIfAbsent(curve, keys);
        }
        for (Map.Entry<EC_Curve, List<EC_Key.Public>> e : curves.entrySet()) {
            EC_Curve curve = e.getKey();
            List<EC_Key.Public> keys = e.getValue();

            tests.add(new Test.Simple(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Test.Result.SUCCESS));
            tests.add(new Test.Simple(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Test.Result.SUCCESS));
            tests.add(new Test.Simple(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL), Test.Result.SUCCESS));
            for (EC_Key.Public pub : keys) {
                // tests.add(new Test.Simple(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, pub.getParams(), pub.flatten()), Test.Result.ANY));
                // tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ANY), Test.Result.FAILURE));
                tests.add(new Test.Simple(new Command.ECDH_direct(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ANY, pub.flatten()), Test.Result.FAILURE));
            }
            tests.add(new Test.Simple(new Command.Cleanup(cardManager), Test.Result.ANY));
        }

        return super.run(cardManager);
    }
}
