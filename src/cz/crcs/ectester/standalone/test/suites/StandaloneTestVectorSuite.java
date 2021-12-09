package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTest;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTestable;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

/**
 * @author David Hofman
 */
public class StandaloneTestVectorSuite extends StandaloneTestSuite {

    public StandaloneTestVectorSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "test-vectors", "The test-vectors suite contains a collection of test vectors which test basic ECDH correctness.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_KAResult> results = EC_Store.getInstance().getObjects(EC_KAResult.class, "test");
        for (EC_KAResult result : results.values()) {
            if(!"DH_PLAIN".equals(result.getKA())) {
                continue;
            }

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

            ECPrivateKey privkey = onekey instanceof EC_Keypair ?
                    (ECPrivateKey) ECUtil.toKeyPair((EC_Keypair) onekey).getPrivate() :
                    ECUtil.toPrivateKey((EC_Key.Private) onekey);
            ECPublicKey pubkey = otherkey instanceof EC_Keypair ?
                    (ECPublicKey) ECUtil.toKeyPair((EC_Keypair) otherkey).getPublic() :
                    ECUtil.toPublicKey((EC_Key.Public) otherkey);

            KeyAgreementIdent kaIdent = KeyAgreementIdent.get("ECDH");
            KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
            KeyAgreementTestable testable = new KeyAgreementTestable(ka, privkey, pubkey);
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Test vector " + result.getId(), KeyAgreementTest.match(testable, result.getData(0))));
        }
    }
}
