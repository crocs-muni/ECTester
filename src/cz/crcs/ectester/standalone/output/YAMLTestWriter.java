package cz.crcs.ectester.standalone.output;

import cz.crcs.ectester.common.output.BaseYAMLTestWriter;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.standalone.test.KeyAgreementTestable;
import cz.crcs.ectester.standalone.test.KeyGeneratorTestable;
import cz.crcs.ectester.standalone.test.SignatureTestable;

import java.io.PrintStream;
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

    private Map<String, Object> kaObject(KeyAgreementTestable kat) {
        Map<String, Object> katObject = new HashMap<>();
        katObject.put("secret", ByteUtil.bytesToHex(kat.getSecret()));
        return katObject;
    }

    private Map<String, Object> kgtObject(KeyGeneratorTestable kgt) {
        Map<String, Object> kgtObject = new HashMap<>();
        Map<String, Object> pubObject = new HashMap<>();
        PublicKey pkey = kgt.getKeyPair().getPublic();
        pubObject.put("algorithm", pkey.getAlgorithm());
        pubObject.put("format", pkey.getFormat());
        pubObject.put("raw", ByteUtil.bytesToHex(pkey.getEncoded()));
        kgtObject.put("pubkey", pubObject);

        Map<String, Object> privObject = new HashMap<>();
        PrivateKey skey = kgt.getKeyPair().getPrivate();
        privObject.put("algorithm", skey.getAlgorithm());
        privObject.put("format", skey.getFormat());
        privObject.put("raw", ByteUtil.bytesToHex(skey.getEncoded()));
        kgtObject.put("privkey", privObject);
        return kgtObject;
    }

    private Map<String, Object> sigObject(SignatureTestable sig) {
        Map<String, Object> sigObject = new HashMap<>();
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
}
