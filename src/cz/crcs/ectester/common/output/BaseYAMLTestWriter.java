package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.*;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

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
        testRun = new LinkedHashMap<>();
        testSuite = new LinkedHashMap<>();
        tests = new LinkedList<>();
        testSuite.put("name", suite.getName());
        testSuite.put("desc", suite.getTextDescription());

        DateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
        Date date = new Date();
        testRun.put("date", dateFormat.format(date));
        testRun.put("suite", testSuite);
        testRun.put("device", deviceObject(suite));
        testRun.put("tests", tests);
    }

    abstract protected Map<String, Object> testableObject(Testable t);

    abstract protected Map<String, Object> deviceObject(TestSuite suite);

    private Object causeObject(Object cause) {
        if (cause == null) {
            return null;
        } else if (cause instanceof Throwable) {
            StringBuilder sb = new StringBuilder();
            for (Throwable t = (Throwable) cause; t != null; t = t.getCause()) {
                sb.append(t.toString());
                sb.append(System.lineSeparator());
            }
            return sb.toString();
        } else {
            return cause.toString();
        }
    }

    private Map<String, Object> resultObject(Result result) {
        Map<String, Object> resultObject = new LinkedHashMap<>();
        resultObject.put("ok", result.ok());
        resultObject.put("value", result.getValue().name());
        resultObject.put("cause", causeObject(result.getCause()));
        return resultObject;
    }

    private Map<String, Object> testObject(Test t, int index) {
        Map<String, Object> testObj;
        if (t instanceof CompoundTest) {
            CompoundTest test = (CompoundTest) t;
            testObj = new HashMap<>();
            testObj.put("type", "compound");
            List<Map<String, Object>> innerTests = new LinkedList<>();
            for (Test innerTest : test.getStartedTests()) {
                innerTests.add(testObject(innerTest, -1));
            }
            testObj.put("tests", innerTests);
        } else {
            SimpleTest<? extends BaseTestable> test = (SimpleTest<? extends BaseTestable>) t;
            testObj = testableObject(test.getTestable());
        }

        testObj.put("desc", t.getDescription());
        testObj.put("result", resultObject(t.getResult()));
        if (index != -1) {
            testObj.put("index", index);
        }

        return testObj;
    }

    @Override
    public void outputTest(Test t, int index) {
        if (!t.hasRun())
            return;
        tests.add(testObject(t, index));
    }

    @Override
    public void outputError(Test t, Throwable cause, int index) {
        tests.add(testObject(t, index));
    }

    @Override
    public void end() {
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        Yaml yaml = new Yaml(options);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("testRun", testRun);
        String out = yaml.dump(result);

        output.println(out);
        output.println("---");
    }
}
