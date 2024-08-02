package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.Ident;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.libs.ProviderECLibrary;

import java.util.Optional;
import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class StandaloneTestSuite extends TestSuite {
    TreeCommandLine cli;
    ECTesterStandalone.Config cfg;

    public StandaloneTestSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli, String name, String... description) {
        super(writer, name, description);
        this.cfg = cfg;
        this.cli = cli;
    }

    public ProviderECLibrary getLibrary() {
        return cfg.selected;
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
                System.err.printf("The default %s algorithm type of \"%s\" was not found. Need to specify a type.", identName, defaultChoice);
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
}
