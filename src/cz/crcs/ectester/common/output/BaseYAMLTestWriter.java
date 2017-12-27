package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.*;
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
public abstract class BaseYAMLTestWriter implements TestWriter {
    private PrintStream output;
    private Map<String, Object> testRun;
    private Map<String, String> testSuite;
    protected List<Object> tests;

    public BaseYAMLTestWriter(PrintStream output) {
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

    abstract protected Map<String, Object> testableObject(Testable t);

    private Map<String, Object> testObject(Test t) {
        Map<String, Object> testObj;
        if (t instanceof CompoundTest) {
            CompoundTest test = (CompoundTest) t;
            testObj = new HashMap<>();
            testObj.put("type", "compound");
            List<Map<String, Object>> innerTests = new LinkedList<>();
            for (Test innerTest : test.getTests()) {
                innerTests.add(testObject(innerTest));
            }
            testObj.put("tests", innerTests);
        } else {
            SimpleTest test = (SimpleTest) t;
            testObj = testableObject(test.getTestable());
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
