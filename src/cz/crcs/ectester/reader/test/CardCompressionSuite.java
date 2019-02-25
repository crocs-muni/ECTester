package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import javacard.security.KeyPair;

import java.security.spec.ECPoint;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardCompressionSuite extends CardTestSuite {
    public CardCompressionSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "compression", null, "The compression test suite tests cards support for compressed points in ECDH (as per ANSI X9.62).",
                "It also tests for handling of bogus input in ECDH by using the point at infinity and a hybrid point with the y coordinate corrupted.",
                "It also tests handling of compressed point in ECDH, where the x coordinate is invalid and therefore",
                "a quadratic non-residue will be computed and (square root-ed) during decompression.");
    }

    @Override
    protected void runTests() throws Exception {
        //iterate over default curve sizes
        // for Fp
        //   - allocate, set custom curve, generate keypairs, -> export generated.
        //   - test ecdh with local and remote simply(no compression)
        //   - test local privkey, remote pubkey (compressed)
        //   - test local privkey, remote pubkey (hybrid)
        //   - test local privkey, remote pubkey (hybrid with wrong y)
        //   - test local privkey, remote pubkey (point at infinity)
        if (cfg.primeField) {
            runCompression(KeyPair.ALG_EC_FP);
        }
        // for F2m
        //   - allocate, set custom curve, generate keypairs, -> export generated.
        //   - test ecdh with local and remote simply(no compression)
        //   - test local privkey, remote pubkey (compressed)
        //   - test local privkey, remote pubkey (hybrid)
        //   - test local privkey, remote pubkey (hybrid with wrong y)
        //   - test local privkey, remote pubkey (point at infinity)
        if (cfg.binaryField) {
            runCompression(KeyPair.ALG_EC_F2M);
        }

        // Now, do ECDH over SECG curves and give the implementation a compressed key that is not a quadratic residue in
        // decompression.
        runNonResidue();
    }

    private void runCompression(byte field) throws Exception {
        short[] keySizes = field == KeyPair.ALG_EC_FP ? EC_Consts.FP_SIZES : EC_Consts.F2M_SIZES;
        short domain = field == KeyPair.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;

        for (short keyLength : keySizes) {
            String spec = keyLength + "b " + CardUtil.getKeyTypeString(field);
            byte curveId = EC_Consts.getCurve(keyLength, field);

            Test allocateFirst = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, field), Result.ExpectedValue.SUCCESS));
            if (!allocateFirst.ok()) {
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "No support for compression test on " + spec + ".", allocateFirst));
                continue;
            }

            List<Test> compressionTests = new LinkedList<>();
            compressionTests.add(allocateFirst);
            Test setCustom = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, curveId, domain, null), Result.ExpectedValue.SUCCESS));
            Test genCustom = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), Result.ExpectedValue.SUCCESS));
            compressionTests.add(setCustom);
            compressionTests.add(genCustom);

            Response.Export key = new Command.Export(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.KEY_PUBLIC, EC_Consts.PARAMETER_W).send();
            byte[] pubkey = key.getParameter(ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.KEY_PUBLIC);
            EC_Curve secgCurve = EC_Store.getInstance().getObject(EC_Curve.class, "secg", CardUtil.getCurveName(curveId));
            ECPoint pub;
            try {
                pub = ECUtil.fromX962(pubkey, secgCurve.toCurve());
            } catch (IllegalArgumentException iae) {
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "", compressionTests.toArray(new Test[0])));
                continue;
            }

            List<Test> kaTests = new LinkedList<>();
            for (byte kaType : EC_Consts.KA_TYPES) {
                List<Test> thisTests = new LinkedList<>();
                Test allocate = runTest(CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), Result.ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Test ka = runTest(CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, kaType), Result.ExpectedValue.SUCCESS));

                    thisTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyAgreement setup and basic test.", allocate, ka));
                    if (ka.ok()) {
                        // tests of the good stuff
                        Test kaCompressed = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_COMPRESS, kaType), Result.ExpectedValue.SUCCESS);
                        Test kaHybrid = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_COMPRESS_HYBRID, kaType), Result.ExpectedValue.SUCCESS);
                        thisTests.add(CompoundTest.any(Result.ExpectedValue.SUCCESS, "Tests of compressed and hybrid form.", kaCompressed, kaHybrid));

                        // tests the bad stuff here
                        byte[] pubHybrid = ECUtil.toX962Hybrid(pub, keyLength);
                        pubHybrid[pubHybrid.length - 1] ^= 1;
                        byte[] pubHybridEncoded = ByteUtil.prependLength(pubHybrid);
                        Test kaBadHybrid = CommandTest.expect(new Command.ECDH_direct(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, kaType, pubHybridEncoded), Result.ExpectedValue.FAILURE);

                        byte[] pubInfinityEncoded = {0x01, 0x00};
                        Test kaBadInfinity = CommandTest.expect(new Command.ECDH_direct(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, kaType, pubInfinityEncoded), Result.ExpectedValue.FAILURE);
                        thisTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests of corrupted hybrid form and infinity.", kaBadHybrid, kaBadInfinity));
                    }
                    kaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyAgreement tests of " + CardUtil.getKATypeString(kaType) + ".", thisTests.toArray(new Test[0])));
                }
            }
            compressionTests.addAll(kaTests);
            if (cfg.cleanup) {
                compressionTests.add(CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.ANY));
            }

            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Compression test of " + spec + ".", compressionTests.toArray(new Test[0])));
        }
    }

    private void runNonResidue() {
        Map<String, EC_Key.Public> otherKeys = EC_Store.getInstance().getObjects(EC_Key.Public.class, "misc");
        List<EC_Key.Public> compressionKeys = EC_Store.mapToPrefix(otherKeys.values()).get("compression");

        for (EC_Key.Public key : compressionKeys) {
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, key.getCurve());
            List<Test> tests = new LinkedList<>();
            Test allocate = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_LOCAL, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS));
            if (!allocate.ok()) {
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "No support for non-residue test on " + curve.getBits() + "b " + curve.getId() + ".", allocate));
                continue;
            }
            tests.add(allocate);
            tests.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS));
            tests.add(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_LOCAL), Result.ExpectedValue.SUCCESS));
            byte[] pointData = ECUtil.toX962Compressed(key.getParam(EC_Consts.PARAMETER_W));
            byte[] pointDataEncoded = ByteUtil.prependLength(pointData);
            tests.add(CommandTest.expect(new Command.ECDH_direct(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH, pointDataEncoded), Result.ExpectedValue.FAILURE));
            doTest(CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Non-residue test of " + curve.getId() + ".", tests.toArray(new Test[0])));
        }
    }
}
