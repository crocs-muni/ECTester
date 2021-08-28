package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_KAResult;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTest;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTestable;

import javax.crypto.KeyAgreement;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

public class StandaloneEdgeCasesSuite extends StandaloneTestSuite {
    public StandaloneEdgeCasesSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "edge-cases", "The edge-cases test suite tests various inputs to ECDH which may cause an implementation to achieve a certain edge-case state during it.",
                "Some of the data is from the google/Wycheproof project. Tests include CVE-2017-10176 and CVE-2017-8932.",
                "Also tests values of the private key and public key that would trigger the OpenSSL modular multiplication bug on the P-256 curve.",
                "Various edge private key values are also tested.",
                "Supports options:",
                "\t - kt/ka-type (select multiple types by separating them with commas)");
    }

    @Override
    protected void runTests() throws Exception {
        String kaAlgo = cli.getOptionValue("test.ka-type");

        KeyAgreementIdent kaIdent;
        if (kaAlgo == null) {
            // try ECDH, if not, fail with: need to specify ka algo.
            Optional<KeyAgreementIdent> kaIdentOpt = cfg.selected.getKAs().stream()
                    .filter((ident) -> ident.contains("ECDH"))
                    .findFirst();
            if (kaIdentOpt.isPresent()) {
                kaIdent = kaIdentOpt.get();
            } else {
                System.err.println("The default KeyAgreement algorithm type of \"ECDH\" was not found. Need to specify a type.");
                return;
            }
        } else {
            // try the specified, if not, fail with: wrong ka algo/not found.
            Optional<KeyAgreementIdent> kaIdentOpt = cfg.selected.getKAs().stream()
                    .filter((ident) -> ident.contains(kaAlgo))
                    .findFirst();
            if (kaIdentOpt.isPresent()) {
                kaIdent = kaIdentOpt.get();
            } else {
                System.err.println("The KeyAgreement algorithm type of \"" + kaAlgo + "\" was not found.");
                return;
            }
        }

        Map<String, EC_KAResult> results = EC_Store.getInstance().getObjects(EC_KAResult.class, "wycheproof");
        Map<String, List<EC_KAResult>> groups = EC_Store.mapToPrefix(results.values());
        for (Map.Entry<String, List<EC_KAResult>> e : groups.entrySet()) {
            String description = null;
            switch (e.getKey()) {
                case "addsub":
                    description = "Tests for addition-subtraction chains.";
                    break;
                case "cve_2017_10176":
                    description = "Tests for CVE-2017-10176.";
                    break;
                case "cve_2017_8932":
                    description = "Tests for CVE-2017-8932.";
                    break;
            }

            List<Test> groupTests = new LinkedList<>();
            Map<EC_Curve, List<EC_KAResult>> curveList = EC_Store.mapResultToCurve(e.getValue());
            for (Map.Entry<EC_Curve, List<EC_KAResult>> c : curveList.entrySet()) {
                EC_Curve curve = c.getKey();

                List<Test> curveTests = new LinkedList<>();
                List<EC_KAResult> values = c.getValue();
                for (EC_KAResult value : values) {
                    String id = value.getId();
                    String privkeyId = value.getOneKey();
                    String pubkeyId = value.getOtherKey();
                    ECPrivateKey ecpriv = ECUtil.toPrivateKey(EC_Store.getInstance().getObject(EC_Key.Private.class, privkeyId));
                    ECPublicKey ecpub = ECUtil.toPublicKey(EC_Store.getInstance().getObject(EC_Key.Public.class, pubkeyId));

                    KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                    KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv, ecpub);
                    Test ecdh = KeyAgreementTest.match(testable, value.getData(0));
                    Test one = CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Test " + id + ".", ecdh);
                    curveTests.add(one);
                }
                groupTests.add(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Tests on " + curve.getId() + ".", curveTests.toArray(new Test[0])));
            }
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, description, groupTests.toArray(new Test[0])));
        }
    }
}
