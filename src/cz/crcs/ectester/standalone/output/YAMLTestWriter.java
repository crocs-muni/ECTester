package cz.crcs.ectester.standalone.output;

import cz.crcs.ectester.common.output.BaseYAMLTestWriter;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.test.KeyAgreementTestable;
import cz.crcs.ectester.standalone.test.KeyGeneratorTestable;
import cz.crcs.ectester.standalone.test.SignatureTestable;
import cz.crcs.ectester.standalone.test.StandaloneTestSuite;

import java.io.PrintStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class YAMLTestWriter extends BaseYAMLTestWriter {
    public YAMLTestWriter(PrintStream output) {
        super(output);
    }

    private Map<String, Object> keyObject(Key key) {
        Map<String, Object> kObject = new HashMap<>();
        if (key == null) {
            return kObject;
        }
        kObject.put("algo", key.getAlgorithm());
        kObject.put("format", key.getFormat());
        kObject.put("raw", ByteUtil.bytesToHex(key.getEncoded()));
        return kObject;
    }

    private Map<String, Object> kaObject(KeyAgreementTestable kat) {
        Map<String, Object> katObject = new HashMap<>();
        katObject.put("algo", kat.getKa().getAlgorithm());
        katObject.put("secret", ByteUtil.bytesToHex(kat.getSecret()));

        PublicKey pkey = kat.getPublicKey();
        katObject.put("pubkey", keyObject(pkey));

        PrivateKey skey = kat.getPrivateKey();
        katObject.put("privkey", keyObject(skey));
        return katObject;
    }

    private Map<String, Object> kgtObject(KeyGeneratorTestable kgt) {
        Map<String, Object> kgtObject = new HashMap<>();
        kgtObject.put("algo", kgt.getKpg().getAlgorithm());

        Map<String, Object> keypair = new HashMap<>();
        if (kgt.getKeyPair() != null) {
            PublicKey pkey = kgt.getKeyPair().getPublic();
            Map<String, Object> pubObject = keyObject(pkey);
            keypair.put("pubkey", pubObject);

            PrivateKey skey = kgt.getKeyPair().getPrivate();
            Map<String, Object> privObject = keyObject(skey);
            keypair.put("privkey", privObject);
        }

        kgtObject.put("keypair", keypair);
        return kgtObject;
    }

    private Map<String, Object> sigObject(SignatureTestable sig) {
        Map<String, Object> sigObject = new HashMap<>();
        sigObject.put("algo", sig.getSig().getAlgorithm());
        sigObject.put("verified", sig.getVerified());
        sigObject.put("raw", ByteUtil.bytesToHex(sig.getSignature()));
        return sigObject;
    }

    @Override
    protected Map<String, Object> testableObject(Testable t) {
        Map<String, Object> result = new HashMap<>();
        if (t instanceof KeyGeneratorTestable) {
            result.put("type", "key-pair-generator");
            result.put("key-pair-generator", kgtObject((KeyGeneratorTestable) t));
        } else if (t instanceof KeyAgreementTestable) {
            result.put("type", "key-agreement");
            result.put("key-agreement", kaObject((KeyAgreementTestable) t));
        } else if (t instanceof SignatureTestable) {
            result.put("type", "signature");
            result.put("signature", sigObject((SignatureTestable) t));
        }
        return result;
    }

    @Override
    protected Map<String, Object> deviceObject(TestSuite suite) {
        if (suite instanceof StandaloneTestSuite) {
            StandaloneTestSuite standaloneSuite = (StandaloneTestSuite) suite;
            Map<String, Object> result = new HashMap<>();
            result.put("type", "library");
            result.put("ectester", ECTesterStandalone.VERSION);
            result.put("name", standaloneSuite.getLibrary().name());
            return result;
        }
        return null;
    }
}
