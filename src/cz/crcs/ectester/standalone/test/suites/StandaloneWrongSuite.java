package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author David Hofman
 */
public class StandaloneWrongSuite extends StandaloneTestSuite {
    private KeyAgreementIdent kaIdent;
    private KeyPairGenerator kpg;

    public StandaloneWrongSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "wrong", "The wrong curve suite tests whether the library rejects domain parameters which are not curves.",
                "Supports options:",
                "\t - gt/kpg-type",
                "\t - kt/ka-type",
                "\t - skip (place this option before the library name to skip tests that can potentially cause a freeze)");
    }


    @Override
    protected void runTests() throws Exception {
        String kpgAlgo = cli.getOptionValue("test.kpg-type");
        String kaAlgo = cli.getOptionValue("test.ka-type");
        boolean skip = cli.getArg(1).equalsIgnoreCase("-skip");

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
        kpg = kpgIdent.getInstance(cfg.selected.getProvider());

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

        /* Just do the default run on the wrong curves.
         * These should generally fail, the curves aren't curves.
         */
        if(!skip) {
            Map<String, EC_Curve> wrongCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "wrong");
            for (Map.Entry<String, EC_Curve> e : wrongCurves.entrySet()) {

                EC_Curve curve = e.getValue();
                ECParameterSpec spec = curve.toSpec();
                String type = curve.getField() == javacard.security.KeyPair.ALG_EC_FP ? "FP" : "F2M";

                //try generating a keypair
                KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);
                Test generate = KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
                runTest(generate);
                KeyPair kp = kgt.getKeyPair();
                if (kp == null) {
                    Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on " + curve.getId() + ".", generate);
                    doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Wrong curve test of " + curve.getBits()
                            + "b " + type + ". " + curve.getDesc(), generateFail));
                    continue;
                }
                Test generateSuccess = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate keypair.", generate);
                ECPrivateKey ecpriv = (ECPrivateKey) kp.getPrivate();
                ECPublicKey ecpub = (ECPublicKey) kp.getPublic();

                KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv, ecpub);
                Test ecdh = KeyAgreementTest.expectError(testable, Result.ExpectedValue.FAILURE);
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Wrong curve test of " + curve.getBits()
                        + "b " + type + ". " + curve.getDesc(), generateSuccess, ecdh));
            }
        }

        /*
         * Do some interesting tests with corrupting the custom curves.
         * For prime field:
         *  - p = 0
         *  - p = 1
         *  - p is a square of a prime
         *  - p is a composite q * s with q, s primes
         *  - TODO: p divides discriminant
         */
        Map<String, EC_Curve> curveMap = EC_Store.getInstance().getObjects(EC_Curve.class, "secg");
        List<EC_Curve> curves = curveMap.entrySet().stream().filter((e) -> e.getKey().endsWith("r1") &&
                e.getValue().getField() == javacard.security.KeyPair.ALG_EC_FP).map(Map.Entry::getValue).collect(Collectors.toList());
        Random r = new Random();
        for (EC_Curve curve : curves) {
            short bits = curve.getBits();
            final byte[] originalp = curve.getParam(EC_Consts.PARAMETER_FP)[0];

            curve.setParam(EC_Consts.PARAMETER_FP, new byte[][]{ ByteUtil.hexToBytes("0")});
            Test prime0 = ecdhTest(toCustomSpec(curve),"ECDH with p = 0.");

            curve.setParam(EC_Consts.PARAMETER_FP, new byte[][]{ ByteUtil.hexToBytes("1")});
            Test prime1 = ecdhTest(toCustomSpec(curve),"ECDH with p = 1.");

            short keyHalf = (short) (bits / 2);
            BigInteger prime = new BigInteger(keyHalf, 50, r);
            BigInteger primePow = prime.pow(2);
            byte[] primePowBytes = ECUtil.toByteArray(primePow, bits);
            curve.setParam(EC_Consts.PARAMETER_FP, new byte[][]{primePowBytes});

            Test primePower = ecdhTest(toCustomSpec(curve), "ECDH with p = q^2.");

            BigInteger q = new BigInteger(keyHalf, r);
            BigInteger s = new BigInteger(keyHalf, r);
            BigInteger compositeValue = q.multiply(s);
            byte[] compositeBytes = ECUtil.toByteArray(compositeValue, bits);
            curve.setParam(EC_Consts.PARAMETER_FP, new byte[][]{compositeBytes});

            Test composite = ecdhTest(toCustomSpec(curve), "ECDH with p = q * s.");

            Test wrongPrime = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with corrupted prime parameter.", prime0 , prime1, primePower, composite );

            curve.setParam(EC_Consts.PARAMETER_FP, new byte[][] {originalp});
            final byte[][] originalG = curve.getParam(EC_Consts.PARAMETER_G);

            byte[] Gx = new BigInteger(curve.getBits(), r).toByteArray();
            byte[] Gy = new BigInteger(curve.getBits(), r).toByteArray();
            curve.setParam(EC_Consts.PARAMETER_G, new byte[][] {Gx, Gy});
            Test fullRandomG = ecdhTest(toCustomSpec(curve), "ECDH with G = random data.");

            final BigInteger originalBigp = new BigInteger(1, originalp);
            byte[] smallerGx = new BigInteger(curve.getBits(), r).mod(originalBigp).toByteArray();
            byte[] smallerGy = new BigInteger(curve.getBits(), r).mod(originalBigp).toByteArray();
            curve.setParam(EC_Consts.PARAMETER_G, new byte[][] {smallerGx, smallerGy});
            Test randomG = ecdhTest(toCustomSpec(curve), "ECDH with G = random data mod p.");

            curve.setParam(EC_Consts.PARAMETER_G, new byte[][] {ByteUtil.hexToBytes("0"), ByteUtil.hexToBytes("0")});
            Test zeroG = ecdhTest(toCustomSpec(curve), "ECDH with G = infinity.");

            Test wrongG = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with corrupted G parameter.", fullRandomG, randomG, zeroG);

            curve.setParam(EC_Consts.PARAMETER_G, originalG);
            final byte[] originalR = curve.getParam(EC_Consts.PARAMETER_R)[0];
            final BigInteger originalBigR = new BigInteger(1, originalR);

            List<Test> allRTests = new LinkedList<>();
            if(!skip) {
                byte[] RZero = new byte[]{(byte) 0};
                curve.setParam(EC_Consts.PARAMETER_R, new byte[][]{RZero});
                allRTests.add(ecdhTest(toCustomSpec(curve), "ECDH with R = 0."));


                byte[] ROne = new byte[]{(byte) 1};
                curve.setParam(EC_Consts.PARAMETER_R, new byte[][]{ROne});
                allRTests.add(ecdhTest(toCustomSpec(curve), "ECDH with R = 1."));
            }

            BigInteger prevPrimeR;
            do {
                prevPrimeR = BigInteger.probablePrime(originalBigR.bitLength() - 1, r);
            } while (prevPrimeR.compareTo(originalBigR) >= 0);
            byte[] prevRBytes = ECUtil.toByteArray(prevPrimeR, bits);
            curve.setParam(EC_Consts.PARAMETER_R, new byte[][] {prevRBytes});
            allRTests.add(ecdhTest(toCustomSpec(curve), "ECDH with R = some prime (but [r]G != infinity) smaller than original R."));

            BigInteger nextPrimeR = originalBigR.nextProbablePrime();
            byte[] nextRBytes = ECUtil.toByteArray(nextPrimeR, bits);
            curve.setParam(EC_Consts.PARAMETER_R, new byte[][]{nextRBytes});
            allRTests.add(ecdhTest(toCustomSpec(curve), "ECDH with R = some prime (but [r]G != infinity) larger than original R."));

            byte[] nonprimeRBytes = nextRBytes.clone();
            nonprimeRBytes[nonprimeRBytes.length - 1] ^= 1;
            curve.setParam(EC_Consts.PARAMETER_R, new byte[][] {nonprimeRBytes} );
            allRTests.add(ecdhTest(toCustomSpec(curve), "ECDH with R = some composite (but [r]G != infinity)."));

            Test wrongR = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with corrupted R parameter.", allRTests.toArray(new Test[0]));

            curve.setParam(EC_Consts.PARAMETER_R, new byte[][] {originalR});

            byte[] kRaw = new byte[]{(byte) 0xff};
            curve.setParam(EC_Consts.PARAMETER_K, new byte[][] {kRaw});
            Test bigK = ecdhTest(toCustomSpec(curve), "ECDH with big K.");

            byte[] kZero = new byte[]{(byte) 0};
            curve.setParam(EC_Consts.PARAMETER_K, new byte[][]{kZero});
            Test zeroK = ecdhTest(toCustomSpec(curve), "ECDH with K = 0.");

            Test wrongK = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with corrupted K parameter.", bigK, zeroK);
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests of " + bits + "b " + "FP", wrongPrime, wrongG, wrongR , wrongK));
        }


        /*
         * For binary field:
         *  - e1 = e2 = e3 = 0
         *  - e1, e2 or e3 is larger than m.
         */
        curveMap = EC_Store.getInstance().getObjects(EC_Curve.class, "secg");
        curves = curveMap.entrySet().stream().filter((e) -> e.getKey().endsWith("r1") &&
                e.getValue().getField() == javacard.security.KeyPair.ALG_EC_F2M).map(Map.Entry::getValue).collect(Collectors.toList());
        for (EC_Curve curve : curves) {
            short bits = curve.getBits();
            byte[][] coeffBytes;


            coeffBytes = new byte[][]{
                    ByteUtil.shortToBytes(bits),
                    ByteUtil.shortToBytes((short) 0),
                    ByteUtil.shortToBytes((short) 0),
                    ByteUtil.shortToBytes((short) 0)};
            curve.setParam(EC_Consts.PARAMETER_F2M, coeffBytes);
            Test coeff0 = ecdhTest(toCustomSpec(curve), "ECDH with wrong field polynomial: x^");

            short e1 = (short) (2 * bits);
            short e2 = (short) (3 * bits);
            short e3 = (short) (4 * bits);
            coeffBytes = new byte[][]{
                    ByteUtil.shortToBytes(bits),
                    ByteUtil.shortToBytes(e1),
                    ByteUtil.shortToBytes(e2),
                    ByteUtil.shortToBytes(e3)};
            curve.setParam(EC_Consts.PARAMETER_F2M, coeffBytes);
            Test coeffLarger = ecdhTest(toCustomSpec(curve), "ECDH with wrong field poly, powers larger than " + bits);

            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with corrupted field polynomial parameter over " + curve.getBits() + "b F2M", coeff0, coeffLarger));
        }
    }

    private Test ecdhTest(ECParameterSpec spec, String desc) throws NoSuchAlgorithmException {
        //generate KeyPair
        KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);
        Test generate =  KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.FAILURE);
        runTest(generate);
        KeyPair kp = kgt.getKeyPair();
        if(kp == null) {
            return CompoundTest.all(Result.ExpectedValue.SUCCESS, desc, generate);
        }
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();

        //perform ECDH
        KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
        KeyAgreementTestable testable = new KeyAgreementTestable(ka, priv, pub);
        Test ecdh = KeyAgreementTest.expect(testable, Result.ExpectedValue.FAILURE);
        return CompoundTest.all(Result.ExpectedValue.SUCCESS, desc, generate, ecdh);
    }

    //constructs EllipticCurve from EC_Curve even if the parameters of the curve are wrong
    private EllipticCurve toCustomCurve(EC_Curve curve) {
        ECField field;
        if (curve.getField() == javacard.security.KeyPair.ALG_EC_FP) {
            field = new CustomECFieldFp(new BigInteger(1, curve.getData(0)));
        } else {
            byte[][] fieldData = curve.getParam(EC_Consts.PARAMETER_F2M);
            int m = ByteUtil.getShort(fieldData[0], 0);
            int e1 = ByteUtil.getShort(fieldData[1], 0);
            int e2 = ByteUtil.getShort(fieldData[2], 0);
            int e3 = ByteUtil.getShort(fieldData[3], 0);
            int[] powers;
            if (e2 == 0 && e3 == 0) {
                powers = new int[]{e1};
            } else {
                powers = new int[]{e1, e2, e3};
            }
            field = new CustomECFieldF2m(m, powers);
        }

        BigInteger a = new BigInteger(1, curve.getParam(EC_Consts.PARAMETER_A)[0]);
        BigInteger b = new BigInteger(1, curve.getParam(EC_Consts.PARAMETER_B)[0]);

        return new CustomEllipticCurve(field, a, b);
    }

    //constructs ECParameterSpec from EC_Curve even if the parameters of the curve are wrong
    private ECParameterSpec toCustomSpec(EC_Curve curve) {
        EllipticCurve customCurve = toCustomCurve(curve);

        byte[][] G = curve.getParam(EC_Consts.PARAMETER_G);
        BigInteger gx = new BigInteger(1, G[0]);
        BigInteger gy = new BigInteger(1, G[1]);
        ECPoint generator = new ECPoint(gx, gy);

        BigInteger n = new BigInteger(1, curve.getParam(EC_Consts.PARAMETER_R)[0]);

        int h = new BigInteger(1, curve.getParam(EC_Consts.PARAMETER_K)[0]).intValue();
        return new CustomECParameterSpec(customCurve, generator, n, h);
    }
}
