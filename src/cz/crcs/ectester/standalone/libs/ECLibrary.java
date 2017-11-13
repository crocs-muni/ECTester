package cz.crcs.ectester.standalone.libs;

import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;

import java.util.Set;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface ECLibrary {
    boolean initialize();

    boolean isInitialized();

    Set<KeyAgreementIdent> getECKAs();

    Set<SignatureIdent> getECSigs();

    Set<KeyPairGeneratorIdent> getKPGs();

    String name();
}
