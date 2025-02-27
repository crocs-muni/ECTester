package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.Util;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.Ident;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.libs.ProviderECLibrary;
import cz.crcs.ectester.standalone.test.base.*;

import javax.crypto.KeyAgreement;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class StandaloneTestSuite extends TestSuite {
    TreeCommandLine cli;
    ECTesterStandalone.Config cfg;
    SecureRandom random;
    byte[] seed;

    public StandaloneTestSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli, String name, String... description) {
        super(writer, name, description);
        this.cfg = cfg;
        this.cli = cli;
        if (cli != null && cli.hasOption("test.prng-seed")) {
            String seedString = cli.getOptionValue("test.prng-seed");
            this.seed = ByteUtil.hexToBytes(seedString, true);
        } else {
            seed = new SecureRandom().generateSeed(16);
        }
        this.random = Util.getRandom(seed);
    }

    public ProviderECLibrary getLibrary() {
        return cfg.selected;
    }

    public byte[] getSeed() {
        return seed;
    }

    SecureRandom getRandom() {
        return this.random;
    }

    public int getNumRepeats() {
        return Integer.parseInt(cli.getOptionValue("test.number", "1"));
    }

    private <T extends Ident> T getIdent(Set<T> options, String choice, String identName, String defaultChoice) {
        T ident;
        if (choice == null) {
            // try EC, if not, fail with: need to specify kpg algo.
            Optional<T> identOpt = options.stream()
                    .filter((i) -> i.contains(defaultChoice))
                    .findFirst();
            if (identOpt.isPresent()) {
                ident = identOpt.get();
            } else {
                System.err.printf("The default %s algorithm type of \"%s\" (default) was not found. Need to specify a type.", identName, defaultChoice);
                return null;
            }
        } else {
            // try the specified, if not, fail with: wrong kpg algo/not found.
            Optional<T> identOpt = options.stream()
                    .filter((i) -> i.contains(choice))
                    .findFirst();
            if (identOpt.isPresent()) {
                ident = identOpt.get();
            } else {
                System.err.printf("The %s algorithm type of \"%s\" was not found.", identName, choice);
                return null;
            }
        }
        return ident;
    }

    KeyPairGeneratorIdent getKeyPairGeneratorIdent(String kpgAlgo) {
        return getIdent(cfg.selected.getKPGs(), kpgAlgo, "KeyPairGenerator", "EC");
    }

    KeyAgreementIdent getKeyAgreementIdent(String kaAlgo) {
        return getIdent(cfg.selected.getKAs(), kaAlgo, "KeyAgreement", "ECDH");
    }

    SignatureIdent getSignatureIdent(String sigAlgo) {
        return getIdent(cfg.selected.getSigs(), sigAlgo, "Signature", "ECDSA");
    }

    public void testCurve(EC_Curve curve, KeyPairGenerator kpg, Result.ExpectedValue expected, String description, String kaAlgo, String sigAlgo, List<String> kaTypes, List<String> sigTypes) throws NoSuchAlgorithmException {
        //generate KeyPair
        KeyGeneratorTestable kgt = KeyGeneratorTestable.builder().keyPairGenerator(kpg).spec(curve.toSpec()).random(getRandom()).build();
        Test generate = KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);

        //perform KeyAgreement tests
        List<Test> kaTests = new LinkedList<>();
        for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
            if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                KeyAgreementTestable testable = KeyAgreementTestable.builder().ka(ka).publicKgt(kgt).privateKgt(kgt).random(getRandom()).build();
                kaTests.add(KeyAgreementTest.expectError(testable, expected));
            }
        }
        if (kaTests.isEmpty()) {
            kaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified KeyAgreement types is supported by the library."));
        }

        //perform Signature tests
        List<Test> sigTests = new LinkedList<>();
        for (SignatureIdent sigIdent : cfg.selected.getSigs()) {
            if (sigAlgo == null || sigIdent.containsAny(sigTypes)) {
                Signature sig = sigIdent.getInstance(cfg.selected.getProvider());
                byte[] data = sigIdent.toString().getBytes();
                SignatureTestable testable = new SignatureTestable(sig, kgt, data, getRandom());
                sigTests.add(SignatureTest.expectError(testable, expected));
            }
        }
        if (sigTests.isEmpty()) {
            sigTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified Signature types is supported by the library."));
        }

        Test performKeyAgreements = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform specified KeyAgreements.", kaTests.toArray(new Test[0]));
        Test performSignatures = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform specified Signatures.", sigTests.toArray(new Test[0]));
        doTest(CompoundTest.function(CompoundTest.EXPECT_ALL_SUCCESS, CompoundTest.RUN_ALL_IF_FIRST,  description, generate, performKeyAgreements, performSignatures));
    }
}
