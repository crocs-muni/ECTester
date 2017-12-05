package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import javacard.security.KeyPair;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardInvalidCurvesSuite extends CardTestSuite {

    public CardInvalidCurvesSuite(EC_Store dataStore, ECTesterReader.Config cfg) {
        super(dataStore, cfg, "invalid", "The invalid curve suite tests whether the card rejects points outside of the curve during ECDH.");
    }

    @Override
    public void setup(CardMngr cardManager) throws IOException {
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

            tests.add(CommandTest.expect(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS));
            tests.add(CommandTest.expect(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.SUCCESS));
            tests.add(CommandTest.expect(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL), ExpectedValue.SUCCESS));
            List<Test> ecdhTests = new LinkedList<>();
            for (EC_Key.Public pub : keys) {
                Command ecdhCommand = new Command.ECDH_direct(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ANY, pub.flatten());
                ecdhTests.add(CommandTest.expect(ecdhCommand, ExpectedValue.FAILURE, "Card correctly rejected point on invalid curve." , "Card incorrectly accepted point on invalid curve."));
            }
            tests.add(CompoundTest.all(ExpectedValue.SUCCESS, "Invalid curve test of " + curve.getId(), ecdhTests.toArray(new Test[0])));
            tests.add(CommandTest.expect(new Command.Cleanup(cardManager), ExpectedValue.ANY));
        }
    }
}
