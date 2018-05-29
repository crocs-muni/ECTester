package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.test.base.*;

import javax.crypto.KeyAgreement;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECParameterSpec;
import java.util.Optional;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class StandaloneDefaultSuite extends StandaloneTestSuite {

    public StandaloneDefaultSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "default", "The default test suite run basic support of ECDH and ECDSA.", "Supports options:", "\t - gt/kpg-type", "\t - kt/ka-type", "\t - st/sig-type", "\t - key-type");
    }

    @Override
    protected void runTests() throws Exception {
        String kpgAlgo = cli.getOptionValue("test.kpg-type");
        String kaAlgo = cli.getOptionValue("test.ka-type");
        String sigAlgo = cli.getOptionValue("test.sig-type");
        String keyAlgo = cli.getOptionValue("test.key-type", "AES");


        KeyPairGeneratorIdent kpgIdent;
        if (kpgAlgo == null) {
            // try EC, if not, fail with: need to specify kpg algo.
            Optional<KeyPairGeneratorIdent> kpgIdentOpt = cfg.selected.getKPGs().stream()
                    .filter((ident) -> ident.contains("EC"))
                    .findFirst();
            if (kpgIdentOpt.isPresent()) {
                kpgIdent = kpgIdentOpt.get();
            } else {
                System.err.println("The default KeyPairGenerator algorithm type of \"EC\" was not found. Need to specify a type.");
                return;
            }
        } else {
            // try the specified, if not, fail with: wrong kpg algo/not found.
            Optional<KeyPairGeneratorIdent> kpgIdentOpt = cfg.selected.getKPGs().stream()
                    .filter((ident) -> ident.contains(kpgAlgo))
                    .findFirst();
            if (kpgIdentOpt.isPresent()) {
                kpgIdent = kpgIdentOpt.get();
            } else {
                System.err.println("The KeyPairGenerator algorithm type of \"" + kpgAlgo + "\" was not found.");
                return;
            }
        }

        KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());

        KeyGeneratorTestable kgtOne;
        KeyGeneratorTestable kgtOther;
        ECParameterSpec spec = null;
        if (cli.hasOption("test.bits")) {
            int bits = Integer.parseInt(cli.getOptionValue("test.bits"));
            kgtOne = new KeyGeneratorTestable(kpg, bits);
            kgtOther = new KeyGeneratorTestable(kpg, bits);
        } else if (cli.hasOption("test.named-curve")) {
            String curveName = cli.getOptionValue("test.named-curve");
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
            if (curve == null) {
                System.err.println("Curve not found: " + curveName);
                return;
            }
            spec = curve.toSpec();
            kgtOne = new KeyGeneratorTestable(kpg, spec);
            kgtOther = new KeyGeneratorTestable(kpg, spec);
        } else {
            kgtOne = new KeyGeneratorTestable(kpg);
            kgtOther = new KeyGeneratorTestable(kpg);
        }

        doTest(KeyGeneratorTest.expect(kgtOne, Result.ExpectedValue.SUCCESS));
        doTest(KeyGeneratorTest.expect(kgtOther, Result.ExpectedValue.SUCCESS));

        for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
            if (kaAlgo == null || kaIdent.contains(kaAlgo)) {
                KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                KeyAgreementTestable testable;
                if (kaIdent.requiresKeyAlgo()) {
                    testable = new KeyAgreementTestable(ka, kgtOne, kgtOther, spec, keyAlgo);
                } else {
                    testable = new KeyAgreementTestable(ka, kgtOne, kgtOther, spec);
                }
                doTest(KeyAgreementTest.expect(testable, Result.ExpectedValue.SUCCESS));
            }
        }
        for (SignatureIdent sigIdent : cfg.selected.getSigs()) {
            if (sigAlgo == null || sigIdent.contains(sigAlgo)) {
                Signature sig = sigIdent.getInstance(cfg.selected.getProvider());
                doTest(SignatureTest.expect(new SignatureTestable(sig, kgtOne, null), Result.ExpectedValue.SUCCESS));
            }
        }
    }
}
