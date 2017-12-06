package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.CommandTest;
import cz.crcs.ectester.standalone.test.*;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.PrintStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class YAMLTestWriter implements TestWriter {
    private PrintStream output;
    private Map<String, Object> testRun;
    private Map<String, String> testSuite;
    private List<Object> tests;

    public YAMLTestWriter(PrintStream output) {
        this.output = output;
    }

    @Override
    public void begin(TestSuite suite) {
        output.println("---");
        testRun = new HashMap<>();
        testSuite = new HashMap<>();
        tests = new LinkedList<>();
        testSuite.put("name", suite.getName());
        testSuite.put("desc", suite.getDescription());

        testRun.put("suite", testSuite);
        testRun.put("tests", tests);
    }

    private Map<String, Object> commandObject(Command c) {
        Map<String, Object> commandObj = new HashMap<>();
        commandObj.put("apdu", ByteUtil.bytesToHex(c.getAPDU().getBytes()));
        return commandObj;
    }

    private Map<String, Object> responseObject(Response r) {
        Map<String, Object> responseObj = new HashMap<>();
        responseObj.put("successful", r.successful());
        responseObj.put("apdu", ByteUtil.bytesToHex(r.getAPDU().getBytes()));
        responseObj.put("natural_sw", Short.toUnsignedInt(r.getNaturalSW()));
        List<Integer> sws = new LinkedList<>();
        for (int i = 0; i < r.getNumSW(); ++i) {
            sws.add(Short.toUnsignedInt(r.getSW(i)));
        }
        responseObj.put("sws", sws);
        responseObj.put("duration", r.getDuration());
        responseObj.put("desc", r.getDescription());
        return responseObj;
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

    private Map<String, Object> testObject(Test t) {
        Map<String, Object> testObj = new HashMap<>();

        if (t instanceof CommandTest) {
            CommandTest test = (CommandTest) t;
            testObj.put("type", "command");
            testObj.put("command", commandObject(test.getCommand()));
            testObj.put("response", responseObject(test.getResponse()));
        } else if (t instanceof KeyAgreementTest) {
            KeyAgreementTest test = (KeyAgreementTest) t;
            testObj.put("type", "key-agreement");
            testObj.put("key-agreement", kaObject(test.getTestable()));
        } else if (t instanceof KeyGeneratorTest) {
            KeyGeneratorTest test = (KeyGeneratorTest) t;
            testObj.put("type", "key-pair-generator");
            testObj.put("key-pair-generator", kgtObject(test.getTestable()));
        } else if (t instanceof SignatureTest) {
            SignatureTest test = (SignatureTest) t;
            testObj.put("type", "signature");
            testObj.put("signature", sigObject(test.getTestable()));
        } else if (t instanceof CompoundTest) {
            CompoundTest test = (CompoundTest) t;
            testObj.put("type", "compound");
            List<Map<String, Object>> tests = new LinkedList<>();
            for (Test innerTest : test.getTests()) {
                tests.add(testObject(innerTest));
            }
            testObj.put("tests", tests);
        }

        testObj.put("desc", t.getDescription());
        Map<String, Object> result = new HashMap<>();
        result.put("ok", t.ok());
        result.put("value", t.getResultValue().name());
        result.put("cause", t.getResultCause());
        testObj.put("result", result);

        return testObj;
    }

    @Override
    public void outputTest(Test t) {
        if (!t.hasRun())
            return;
        tests.add(testObject(t));
    }

    @Override
    public void end() {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        Yaml yaml = new Yaml(options);

        Map<String, Object> result = new HashMap<>();
        result.put("testRun", testRun);
        String out = yaml.dump(result);

        output.println(out);
        output.println("---");
    }
}
