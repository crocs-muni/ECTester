package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * @author David Hofman
 */
public class StandaloneMiscSuite extends StandaloneTestSuite {
    private String kpgAlgo;
    private String kaAlgo;
    private String sigAlgo;
    private List<String> kaTypes;
    private List<String> sigTypes;

    public StandaloneMiscSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "miscellaneous", "Some miscellaneous tests, tries ECDH and ECDSA over supersingular curves, anomalous curves,",
                "Barreto-Naehrig curves with small embedding degree and CM discriminant, MNT curves,",
                "some Montgomery curves transformed to short Weierstrass form and Curve25519 transformed to short Weierstrass form.",
                "Supports options:",
                "\t - gt/kpg-type",
                "\t - kt/ka-type (select multiple types by separating them with commas)",
                "\t - st/sig-type (select multiple types by separating them with commas)");
    }

    @Override
    protected void runTests() throws Exception {
        kpgAlgo = cli.getOptionValue("test.kpg-type");
        kaAlgo = cli.getOptionValue("test.ka-type");
        sigAlgo = cli.getOptionValue("test.sig-type");

        kaTypes = kaAlgo != null ? Arrays.asList(kaAlgo.split(",")) : new ArrayList<>();
        sigTypes = sigAlgo != null ? Arrays.asList(sigAlgo.split(",")) : new ArrayList<>();

        KeyPairGeneratorIdent kpgIdent = getKeyPairGeneratorIdent(kpgAlgo);
        if (kpgIdent == null) {
            return;
        }
        KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());

        Map<String, EC_Curve> anCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "anomalous");
        Map<String, EC_Curve> ssCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "supersingular");
        Map<String, EC_Curve> bnCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "Barreto-Naehrig");
        Map<String, EC_Curve> mntCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "MNT");
        List<EC_Curve> mCurves = new ArrayList<>();
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-221"));
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-383"));
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-511"));
        EC_Curve curve25519 = EC_Store.getInstance().getObject(EC_Curve.class, "other", "Curve25519");

        testCurves(anCurves.values(), "anomalous", kpg, Result.ExpectedValue.FAILURE);
        testCurves(ssCurves.values(), "supersingular", kpg, Result.ExpectedValue.FAILURE);
        testCurves(bnCurves.values(), "Barreto-Naehrig", kpg, Result.ExpectedValue.SUCCESS);
        testCurves(mntCurves.values(), "MNT", kpg, Result.ExpectedValue.SUCCESS);
        testCurves(mCurves, "Montgomery", kpg, Result.ExpectedValue.SUCCESS);
        testCurve(curve25519, kpg, Result.ExpectedValue.SUCCESS, "Tests over Curve25519.", kaAlgo, sigAlgo, kaTypes, sigTypes);
    }

    private void testCurves(Collection<EC_Curve> curves, String catName, KeyPairGenerator kpg, Result.ExpectedValue expected) throws NoSuchAlgorithmException {
        for (EC_Curve curve : curves) {
            testCurve(curve, kpg, expected, "Tests over " + curve.getBits() + "b " + catName + " curve: " + curve.getId() + ".", kaAlgo, sigAlgo, kaTypes, sigTypes);
        }
    }
}
