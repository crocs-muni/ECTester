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
import java.util.List;
import java.util.Map;

/**
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CompositeCurvesSuite extends TestSuite {

    public CompositeCurvesSuite(EC_Store dataStore, ECTester.Config cfg, OutputWriter writer) {
        super(dataStore, cfg, writer, "composite");
    }

    @Override
    public List<Test> run(CardMngr cardManager) throws IOException, CardException {
        /* Do the default tests with the public keys set to provided smallorder keys
         * over composite order curves. Essentially small subgroup attacks.
         * These should fail, the curves aren't safe so that if the computation with
         * a small order public key succeeds the private key modulo the public key order
         * is revealed.
         */
        Map<String, EC_Key> keys = dataStore.getObjects(EC_Key.class, "composite");
        for (EC_Key key : keys.values()) {
            EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
            if (cfg.namedCurve != null && !(key.getCurve().startsWith(cfg.namedCurve) || key.getCurve().equals(cfg.namedCurve))) {
                continue;
            }
            if (curve.getField() == KeyPair.ALG_EC_FP && !cfg.primeField || curve.getField() == KeyPair.ALG_EC_F2M && !cfg.binaryField) {
                continue;
            }
            if ((curve.getBits() == cfg.bits || cfg.all)) {
                tests.add(new Test.Simple(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Test.Result.SUCCESS));
                tests.add(new Test.Simple(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Test.Result.ANY));
                tests.add(new Test.Simple(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL), Test.Result.ANY));

                //tests.add(new Test.Simple(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, key.getParams(), key.flatten()), Test.Result.ANY));
                //tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH), Test.Result.FAILURE));
                tests.add(new Test.Simple(new Command.ECDH_direct(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH, key.flatten()), Test.Result.FAILURE));

                tests.add(new Test.Simple(new Command.Cleanup(cardManager), Test.Result.ANY));
            }
        }
        return super.run(cardManager);
    }
}
