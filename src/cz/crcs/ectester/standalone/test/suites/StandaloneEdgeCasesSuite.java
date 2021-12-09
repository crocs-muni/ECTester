package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTest;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTestable;
import cz.crcs.ectester.standalone.test.base.KeyGeneratorTest;
import cz.crcs.ectester.standalone.test.base.KeyGeneratorTestable;

import javax.crypto.KeyAgreement;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author David Hofman
 */
public class StandaloneEdgeCasesSuite extends StandaloneTestSuite {
    KeyAgreementIdent kaIdent;

    public StandaloneEdgeCasesSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "edge-cases", "The edge-cases test suite tests various inputs to ECDH which may cause an implementation to achieve a certain edge-case state during it.",
                "Some of the data is from the google/Wycheproof project. Tests include CVE-2017-10176 and CVE-2017-8932.",
                "Also tests values of the private key and public key that would trigger the OpenSSL modular multiplication bug on the P-256 curve.",
                "Various edge private key values are also tested.",
                "Supports options:",
                "\t - gt/kpg-type",
                "\t - kt/ka-type");
    }

    @Override
    protected void runTests() throws Exception {
        String kaAlgo = cli.getOptionValue("test.ka-type");
        String kpgAlgo = cli.getOptionValue("test.kpg-type");

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
                    Test one = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Test " + id + ".", ecdh);
                    curveTests.add(one);
                }
                groupTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests on " + curve.getId() + ".", curveTests.toArray(new Test[0])));
            }
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, description, groupTests.toArray(new Test[0])));
        }

        {
            EC_KAResult openssl_bug = EC_Store.getInstance().getObject(EC_KAResult.class, "misc", "openssl-bug");
            ECPrivateKey ecpriv = ECUtil.toPrivateKey(EC_Store.getInstance().getObject(EC_Key.Private.class, openssl_bug.getOtherKey()));
            ECPublicKey ecpub = ECUtil.toPublicKey(EC_Store.getInstance().getObject(EC_Key.Public.class, openssl_bug.getOneKey()));
            KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
            KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv, ecpub);
            Test ecdh = KeyAgreementTest.function(testable, new TestCallback<KeyAgreementTestable>() {
                @Override
                public Result apply(KeyAgreementTestable testable) {
                    if (!testable.ok()) {
                        return new Result(Result.Value.FAILURE, "ECDH was unsuccessful.");
                    }
                    if (ByteUtil.compareBytes(testable.getSecret(), 0, openssl_bug.getData(0), 0, testable.getSecret().length)) {
                        return new Result(Result.Value.FAILURE, "OpenSSL bug is present, derived secret matches example.");
                    }
                    return new Result(Result.Value.SUCCESS);
                }
            });

            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Test OpenSSL modular reduction bug.", ecdh));
        }

        Map<String, EC_Curve> curveMap = EC_Store.getInstance().getObjects(EC_Curve.class, "secg");
        List<EC_Curve> curves = curveMap.entrySet().stream().filter((e) ->
                e.getKey().endsWith("r1") && e.getValue().getField() == javacard.security.KeyPair.ALG_EC_FP).map(Map.Entry::getValue).collect(Collectors.toList());
        curves.add(EC_Store.getInstance().getObject(EC_Curve.class, "cofactor/cofactor128p2"));
        curves.add(EC_Store.getInstance().getObject(EC_Curve.class, "cofactor/cofactor160p4"));
        Random rand = new Random();
        for (EC_Curve curve : curves) {
            ECParameterSpec spec = curve.toSpec();

            //generate KeyPair
            KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);
            Test generate = KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
            runTest(generate);
            KeyPair kp = kgt.getKeyPair();
            if (kp == null) {
                Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on " + curve.getId() +
                        ". " + " Other tests will be skipped.", generate);
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with edge-case private key values over" + curve.getId() + ".", generateFail));
                continue;
            }
            Test generateSuccess = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate KeyPair.", generate);
            ECPublicKey ecpub = (ECPublicKey) kp.getPublic();

            //perform ECDH tests
            Test zeroS = ecdhTest(ecpub, BigInteger.ZERO, spec, "ECDH with S = 0.", Result.ExpectedValue.FAILURE);
            Test oneS = ecdhTest(ecpub, BigInteger.ONE, spec, "ECDH with S = 1.", Result.ExpectedValue.FAILURE);

            byte[] rParam = curve.getParam(EC_Consts.PARAMETER_R)[0];
            BigInteger R = new BigInteger(1, rParam);
            BigInteger smaller = new BigInteger(curve.getBits(), rand).mod(R);
            BigInteger diff = R.divide(BigInteger.valueOf(10));
            BigInteger randDiff = new BigInteger(diff.bitLength(), rand).mod(diff);
            BigInteger larger = R.add(randDiff);
            BigInteger full = BigInteger.valueOf(1).shiftLeft(R.bitLength() - 1).subtract(BigInteger.ONE);

            BigInteger alternate = full;
            for (int i = 0; i < R.bitLength(); i += 2) {
                alternate = alternate.clearBit(i);
            }

            BigInteger alternateOther = alternate.xor(full);
            BigInteger rm1 = R.subtract(BigInteger.ONE);
            BigInteger rp1 = R.add(BigInteger.ONE);

            Test alternateS = ecdhTest(ecpub, alternate, spec, "ECDH with S = 101010101...01010.", Result.ExpectedValue.SUCCESS);
            Test alternateOtherS = ecdhTest(ecpub, alternateOther, spec, "ECDH with S = 010101010...10101.", Result.ExpectedValue.SUCCESS);
            Test fullS = ecdhTest(ecpub, full, spec, "ECDH with S = 111111111...11111 (but < r).", Result.ExpectedValue.SUCCESS);
            Test smallerS = ecdhTest(ecpub, smaller, spec, "ECDH with S < r.", Result.ExpectedValue.SUCCESS);
            Test exactS = ecdhTest(ecpub, R, spec, "ECDH with S = r.", Result.ExpectedValue.FAILURE);
            Test largeS = ecdhTest(ecpub, larger, spec, "ECDH with S > r.", Result.ExpectedValue.ANY);
            Test rm1S = ecdhTest(ecpub, rm1, spec, "ECDH with S = r - 1.", Result.ExpectedValue.SUCCESS);
            Test rp1S = ecdhTest(ecpub, rp1, spec, "ECDH with S = r + 1.", Result.ExpectedValue.ANY);

            byte[] k = curve.getParam(EC_Consts.PARAMETER_K)[0];
            BigInteger K = new BigInteger(1, k);
            BigInteger kr = K.multiply(R);
            BigInteger krm1 = kr.subtract(BigInteger.ONE);
            BigInteger krp1 = kr.add(BigInteger.ONE);

            Result.ExpectedValue kExpected = K.equals(BigInteger.ONE) ? Result.ExpectedValue.SUCCESS : Result.ExpectedValue.FAILURE;

            Test krS /*ONE!*/ = ecdhTest(ecpub, kr, spec, "ECDH with S = k * r.", Result.ExpectedValue.FAILURE);
            Test krm1S = ecdhTest(ecpub, krm1, spec, "ECDH with S = (k * r) - 1.", kExpected);
            Test krp1S = ecdhTest(ecpub, krp1, spec, "ECDH with S = (k * r) + 1.", Result.ExpectedValue.ANY);

            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with edge-case private key values over " + curve.getId() + ".",
                    generateSuccess, zeroS, oneS, alternateS, alternateOtherS, fullS, smallerS, exactS, largeS, rm1S, rp1S, krS, krm1S, krp1S));
        }

        EC_Curve secp160r1 = EC_Store.getInstance().getObject(EC_Curve.class, "secg/secp160r1");
        ECParameterSpec spec = secp160r1.toSpec();
        byte[] pData = secp160r1.getParam(EC_Consts.PARAMETER_FP)[0];
        BigInteger p = new BigInteger(1, pData);
        byte[] rData = secp160r1.getParam(EC_Consts.PARAMETER_R)[0];
        BigInteger r = new BigInteger(1, rData);

        BigInteger range = r.subtract(p);
        BigInteger deviation = range.divide(BigInteger.valueOf(5));
        BigDecimal dev = new BigDecimal(deviation);
        BigDecimal smallDev = new BigDecimal(10000);
        int n = 10;
        BigInteger[] rs = new BigInteger[n];
        BigInteger[] ps = new BigInteger[n];
        BigInteger[] zeros = new BigInteger[n];
        for (int i = 0; i < n; ++i) {
            double sample;
            do {
                sample = rand.nextGaussian();
            } while (sample >= -1 && sample <= 1);
            BigInteger where = dev.multiply(new BigDecimal(sample)).toBigInteger();
            rs[i] = where.add(r);
            ps[i] = where.add(p);
            zeros[i] = smallDev.multiply(new BigDecimal(sample)).toBigInteger().abs();
        }
        Arrays.sort(rs);
        Arrays.sort(ps);
        Arrays.sort(zeros);

        //generate KeyPair
        KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);
        Test generate =  KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
        runTest(generate);
        KeyPair kp = kgt.getKeyPair();
        if(kp == null) {
            Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on "
                    + secp160r1.getBits() + "b secp160r1." + " Other tests will be skipped.", generate);
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Test private key values near zero, near p and near/larger than the order on" + secp160r1.getId() + ".", generateFail));
            return;
        }
        Test generateSuccess = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate KeyPair.", generate);
        ECPublicKey ecpub = (ECPublicKey) kp.getPublic();

        //perform ECDH tests
        Test[] zeroTests = new Test[n];
        int i = 0;
        for (BigInteger nearZero : zeros) {
            zeroTests[i++] = ecdhTest(ecpub, nearZero, spec, nearZero.toString(16), Result.ExpectedValue.SUCCESS);
        }
        Test zeroTest = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Near zero.", zeroTests);

        Test[] pTests = new Test[n];
        i = 0;
        for (BigInteger nearP : ps) {
            pTests[i++] = ecdhTest(ecpub, nearP, spec, nearP.toString(16) + (nearP.compareTo(p) > 0 ? " (>p)" : " (<=p)"), Result.ExpectedValue.SUCCESS);
        }
        Test pTest = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Near p.", pTests);

        Test[] rTests = new Test[n];
        i = 0;
        for (BigInteger nearR : rs) {
            if (nearR.compareTo(r) >= 0) {
                rTests[i++] = ecdhTest(ecpub, nearR, spec, nearR.toString(16) + " (>=r)", Result.ExpectedValue.FAILURE);
            } else {
                rTests[i++] = ecdhTest(ecpub, nearR, spec, nearR.toString(16) + " (<r)", Result.ExpectedValue.SUCCESS);
            }
        }
        Test rTest = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Near r.", rTests);
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Test private key values near zero, near p and near/larger than the order.", generateSuccess, zeroTest, pTest, rTest));
    }

    private Test ecdhTest(ECPublicKey pub, BigInteger SParam, ECParameterSpec spec, String desc, Result.ExpectedValue expect) throws NoSuchAlgorithmException {
        ECPrivateKey priv = new RawECPrivateKey(SParam, spec);
        KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
        KeyAgreementTestable testable = new KeyAgreementTestable(ka, priv, pub);
        return CompoundTest.all(Result.ExpectedValue.SUCCESS, desc, KeyAgreementTest.expectError(testable, expect));
    }
}
