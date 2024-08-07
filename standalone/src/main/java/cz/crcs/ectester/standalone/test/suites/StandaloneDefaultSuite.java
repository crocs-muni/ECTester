package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.util.ECUtil;
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

        KeyPairGeneratorIdent kpgIdent = getKeyPairGeneratorIdent(kpgAlgo);
        if (kpgIdent == null) {
            return;
        }
        KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());

        KeyGeneratorTestable kgtOne;
        KeyGeneratorTestable kgtOther;
        ECParameterSpec spec = null;
        if (cli.hasOption("test.bits")) {
            int bits = Integer.parseInt(cli.getOptionValue("test.bits"));
            kgtOne = KeyGeneratorTestable.builder().keyPairGenerator(kpg).keysize(bits).build();
            kgtOther = KeyGeneratorTestable.builder().keyPairGenerator(kpg).keysize(bits).build();
        } else if (cli.hasOption("test.named-curve")) {
            String curveName = cli.getOptionValue("test.named-curve");
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
            if (curve == null) {
                System.err.println("Curve not found: " + curveName);
                return;
            }
            spec = curve.toSpec();
            kgtOne = KeyGeneratorTestable.builder().keyPairGenerator(kpg).spec(spec).build();
            kgtOther = KeyGeneratorTestable.builder().keyPairGenerator(kpg).spec(spec).build();
        } else {
            kgtOne = KeyGeneratorTestable.builder().keyPairGenerator(kpg).build();
            kgtOther = KeyGeneratorTestable.builder().keyPairGenerator(kpg).build();
        }

        doTest(KeyGeneratorTest.expect(kgtOne, Result.ExpectedValue.SUCCESS));
        doTest(KeyGeneratorTest.expect(kgtOther, Result.ExpectedValue.SUCCESS));

        for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
            if (kaAlgo == null || kaIdent.contains(kaAlgo)) {
                KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                KeyAgreementTestable testable;
                if (kaIdent.requiresKeyAlgo()) {
                    testable = KeyAgreementTestable.builder().ka(ka).privateKgt(kgtOne).publicKgt(kgtOther).spec(spec).keyAlgo(keyAlgo).build();
                } else {
                    testable = KeyAgreementTestable.builder().ka(ka).privateKgt(kgtOne).publicKgt(kgtOther).spec(spec).build();
                }
                doTest(KeyAgreementTest.expect(testable, Result.ExpectedValue.SUCCESS));
            }
        }
        for (SignatureIdent sigIdent : cfg.selected.getSigs()) {
            if (sigAlgo == null || sigIdent.contains(sigAlgo)) {
                Signature sig = sigIdent.getInstance(cfg.selected.getProvider());
                byte[] data = sigIdent.toString().getBytes();
                doTest(SignatureTest.expect(new SignatureTestable(sig, kgtOne, data, null), Result.ExpectedValue.SUCCESS));
            }
        }
    }
}
