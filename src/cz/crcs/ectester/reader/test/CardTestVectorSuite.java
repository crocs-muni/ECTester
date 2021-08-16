package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import javacard.security.KeyPair;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;
import static cz.crcs.ectester.common.test.Result.Value;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardTestVectorSuite extends CardTestSuite {

    public CardTestVectorSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "test-vectors", null, "The test-vectors suite contains a collection of test vectors which test basic ECDH correctness.");
    }

    @Override
    protected void runTests() throws Exception {
        /* Set original curves (secg/nist/brainpool). Set keypairs from test vectors.
         * Do ECDH both ways, export and verify that the result is correct.
         */
        Map<String, EC_KAResult> results = EC_Store.getInstance().getObjects(EC_KAResult.class, "test");
        for (EC_KAResult result : results.values()) {
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, result.getCurve());
            EC_Params onekey = EC_Store.getInstance().getObject(EC_Keypair.class, result.getOneKey());
            if (onekey == null) {
                onekey = EC_Store.getInstance().getObject(EC_Key.Private.class, result.getOneKey());
            }
            EC_Params otherkey = EC_Store.getInstance().getObject(EC_Keypair.class, result.getOtherKey());
            if (otherkey == null) {
                otherkey = EC_Store.getInstance().getObject(EC_Key.Public.class, result.getOtherKey());
            }
            if (onekey == null || otherkey == null) {
                throw new IOException("Test vector keys couldn't be located.");
            }
            List<Test> testVector = new LinkedList<>();
            Test allocate = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS));
            if (!allocate.ok()) {
                doTest(CompoundTest.all(ExpectedValue.SUCCESS, "No support for " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()) + ".", allocate));
                continue;
            }

            testVector.add(allocate);
            testVector.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, EC_Consts.PARAMETER_S, onekey.flatten(EC_Consts.PARAMETER_S)), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, EC_Consts.PARAMETER_W, otherkey.flatten(EC_Consts.PARAMETER_W)), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.function(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_TRUE, EC_Consts.TRANSFORMATION_NONE, result.getJavaCardKA()), new TestCallback<CommandTestable>() {
                @Override
                public Result apply(CommandTestable testable) {
                    Response.ECDH dh = (Response.ECDH) testable.getResponse();
                    if (!dh.successful())
                        return new Result(Value.FAILURE, "ECDH was unsuccessful.");
                    if (!dh.hasSecret())
                        return new Result(Value.FAILURE, "ECDH response did not contain the derived secret.");
                    if (!ByteUtil.compareBytes(dh.getSecret(), 0, result.getData(0), 0, dh.secretLength())) {
                        int firstDiff = ByteUtil.diffBytes(dh.getSecret(), 0, result.getData(0), 0, dh.secretLength());
                        return new Result(Value.FAILURE, "ECDH derived secret does not match the test-vector, first difference was at byte " + firstDiff + ".");
                    }
                    return new Result(Value.SUCCESS);
                }
            }));
            if (cfg.cleanup) {
                testVector.add(CommandTest.expect(new Command.Cleanup(this.card), ExpectedValue.ANY));
            }
            doTest(CompoundTest.greedyAll(ExpectedValue.SUCCESS, "Test vector " + result.getId() + ".", testVector.toArray(new Test[0])));
        }

        KeyAgreement ka;
        Signature sig;
        KeyFactory kf;
        MessageDigest md;
        try {
            ka = KeyAgreement.getInstance("ECDH", "BC");
            sig = Signature.getInstance("ECDSAwithSHA1", "BC");
            kf = KeyFactory.getInstance("ECDH", "BC");
            md = MessageDigest.getInstance("SHA1", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            return;
        }

        List<EC_Curve> testCurves = new ArrayList<>();
        testCurves.addAll(EC_Store.getInstance().getObjects(EC_Curve.class, "secg").values().stream().filter((curve) -> curve.getField() == KeyPair.ALG_EC_FP).collect(Collectors.toList()));
        testCurves.addAll(EC_Store.getInstance().getObjects(EC_Curve.class, "brainpool").values().stream().filter((curve) -> curve.getField() == KeyPair.ALG_EC_FP).collect(Collectors.toList()));
        for (EC_Curve curve : testCurves) {
            List<Test> testVector = new LinkedList<>();
            Test allocate = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS));
            if (!allocate.ok()) {
                doTest(CompoundTest.all(ExpectedValue.SUCCESS, "No support for " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()) + ".", allocate));
                continue;
            }
            testVector.add(allocate);
            testVector.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.SUCCESS));
            CommandTest exportLocal = CommandTest.expect(new Command.Export(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, EC_Consts.PARAMETER_W), ExpectedValue.ANY);
            CommandTest exportRemote = CommandTest.expect(new Command.Export(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.KEY_PRIVATE, EC_Consts.PARAMETER_S), ExpectedValue.ANY);
            testVector.add(exportLocal);
            testVector.add(exportRemote);
            BiFunction<Response.Export, Response.Export, Key[]> getKeys = (localData, remoteData) -> {
                byte[] pkey = localData.getParameter(ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.PARAMETER_W);
                byte[] skey = remoteData.getParameter(ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.PARAMETER_S);
                ECParameterSpec spec = curve.toSpec();
                ECPrivateKeySpec privKeySpec = new ECPrivateKeySpec(new BigInteger(1, skey), spec);
                ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(ECUtil.fromX962(pkey, curve.toCurve()), spec);
                PrivateKey privKey;
                PublicKey pubKey;
                try {
                    privKey = kf.generatePrivate(privKeySpec);
                    pubKey = kf.generatePublic(pubKeySpec);
                } catch (InvalidKeySpecException ex) {
                    return null;
                }
                return new Key[]{privKey, pubKey};
            };
            TestCallback<CommandTestable> kaCallback = new TestCallback<CommandTestable>() {
                @Override
                public Result apply(CommandTestable testable) {
                    Response.ECDH ecdhData = (Response.ECDH) testable.getResponse();
                    if (!ecdhData.successful())
                        return new Result(Value.FAILURE, "ECDH was unsuccessful.");
                    if (!ecdhData.hasSecret()) {
                        return new Result(Value.FAILURE, "ECDH response did not contain the derived secret.");
                    }
                    byte[] secret = ecdhData.getSecret();
                    Response.Export localData = (Response.Export) exportLocal.getResponse();
                    Response.Export remoteData = (Response.Export) exportRemote.getResponse();
                    Key[] keys = getKeys.apply(localData, remoteData);
                    if (keys == null) {
                        return new Result(Value.SUCCESS, "Result could not be verified. keyData unavailable.");
                    }
                    PrivateKey privKey = (PrivateKey) keys[0];
                    PublicKey pubKey = (PublicKey) keys[1];
                    try {
                        ka.init(privKey);
                        ka.doPhase(pubKey, true);
                        byte[] derived = ka.generateSecret();
                        int fieldSize = (curve.getBits() + 7) / 8;
                        if (derived.length < fieldSize) {
                            byte[] padded = new byte[fieldSize];
                            System.arraycopy(derived, 0, padded, fieldSize - derived.length, derived.length);
                            derived = padded;
                        }
                        if (ecdhData.getType() == EC_Consts.KeyAgreement_ALG_EC_SVDP_DH || ecdhData.getType() == EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC) {
                            derived = md.digest(derived);
                        }
                        if (secret.length != derived.length) {
                            if (secret.length < derived.length) {
                                return new Result(Value.FAILURE, String.format("Derived secret was shorter than expected: %d vs %d (expected).", secret.length, derived.length));
                            } else {
                                return new Result(Value.FAILURE, String.format("Derived secret was longer than expected: %d vs %d (expected).", secret.length, derived.length));
                            }
                        }
                        int diff = ByteUtil.diffBytes(derived, 0, secret, 0, secret.length);
                        if (diff == secret.length) {
                            return new Result(Value.SUCCESS, "Derived secret matched expected value.");
                        } else {
                            return new Result(Value.FAILURE, "Derived secret does not match expected value, first difference was at byte " + diff + ".");
                        }
                    } catch (InvalidKeyException ex) {
                        return new Result(Value.SUCCESS, "Result could not be verified. " + ex.getMessage());
                    }
                }
            };
            Test ecdhTest = CommandTest.function(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_TRUE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), kaCallback);
            Test ecdhRawTest = CommandTest.function(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_TRUE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN), kaCallback);
            byte[] data = new byte[32];
            TestCallback<CommandTestable> sigCallback = new TestCallback<CommandTestable>() {
                @Override
                public Result apply(CommandTestable testable) {
                    Response.ECDSA ecdsaData = (Response.ECDSA) testable.getResponse();
                    if (!ecdsaData.successful())
                        return new Result(Value.FAILURE, "ECDSA was unsuccessful.");
                    if (!ecdsaData.hasSignature()) {
                        return new Result(Value.FAILURE, "ECDSA response did not contain the signature.");
                    }
                    byte[] signature = ecdsaData.getSignature();
                    Response.Export localData = (Response.Export) exportLocal.getResponse();
                    Response.Export remoteData = (Response.Export) exportRemote.getResponse();
                    Key[] keys = getKeys.apply(localData, remoteData);
                    if (keys == null) {
                        return new Result(Value.SUCCESS, "Result could not be verified. keyData unavailable.");
                    }
                    PublicKey pubKey = (PublicKey) keys[1];
                    try {
                        sig.initVerify(pubKey);
                        sig.update(data);
                        if (sig.verify(signature)) {
                            return new Result(Value.SUCCESS, "Signature verified.");
                        } else {
                            return new Result(Value.FAILURE, "Signature failed to verify.");
                        }
                    } catch (InvalidKeyException | SignatureException ex) {
                        return new Result(Value.SUCCESS, "Result could not be verified. " + ex.getMessage());
                    }
                }
            };
            Test ecdsaTest = CommandTest.function(new Command.ECDSA_sign(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.Signature_ALG_ECDSA_SHA, ECTesterApplet.EXPORT_TRUE, data), sigCallback);
            testVector.add(CompoundTest.all(ExpectedValue.SUCCESS, "Test.", ecdhTest, ecdhRawTest, ecdsaTest));
            if (cfg.cleanup) {
                testVector.add(CommandTest.expect(new Command.Cleanup(this.card), ExpectedValue.ANY));
            }
            doTest(CompoundTest.greedyAll(ExpectedValue.SUCCESS, "Validation test on " + curve.getId() + ".", testVector.toArray(new Test[0])));
        }
    }
}
