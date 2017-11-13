package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.Util;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.reader.test.CommandTest;
import cz.crcs.ectester.reader.test.TestSuite;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.PrintStream;
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
        commandObj.put("apdu", Util.bytesToHex(c.getAPDU().getBytes()));
        return commandObj;
    }

    private Map<String, Object> responseObject(Response r) {
        Map<String, Object> responseObj = new HashMap<>();
        responseObj.put("successful", r.successful());
        responseObj.put("apdu", Util.bytesToHex(r.getAPDU().getBytes()));
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

    private Map<String, Object> testObject(Test t) {
        Map<String, Object> testObj = new HashMap<>();

        if (t instanceof CommandTest) {
            CommandTest test = (CommandTest) t;
            testObj.put("type", "simple");
            testObj.put("command", commandObject(test.getCommand()));
            testObj.put("response", responseObject(test.getResponse()));
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
