package cz.crcs.ectester.standalone.output;

import cz.crcs.ectester.common.cli.Colors;
import cz.crcs.ectester.common.output.BaseTextTestWriter;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.test.base.StandaloneTestable;
import cz.crcs.ectester.standalone.test.suites.StandaloneTestSuite;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TextTestWriter extends BaseTextTestWriter {
    public TextTestWriter(PrintStream output) {
        super(output);
    }

    private String causeString(Object cause) {
        if (cause == null) {
            return "";
        } else if (cause instanceof Exception) {
            Exception ex = ((Exception) cause);
            return " -> " + ex.getClass().getCanonicalName() + " : " + ex.getMessage();
        } else {
            return cause.toString();
        }
    }

    @Override
    protected String testableString(Testable t) {
        if (t instanceof StandaloneTestable) {
            StandaloneTestable<?> testable = (StandaloneTestable) t;
            Enum<?> stage = testable.getStage();
            String stageName = stage.name();
            String exception = causeString(testable.getException());
            String errorCause = causeString(testable.errorCause());
            return String.format("[%d/%d] %s %s %s", stage.ordinal() + 1, stage.getClass().getEnumConstants().length, stageName, exception, errorCause);
        }
        return "";
    }

    @Override
    protected String deviceString(TestSuite suite) {
        if (suite instanceof StandaloneTestSuite) {
            StandaloneTestSuite standaloneSuite = (StandaloneTestSuite) suite;
            StringBuilder sb = new StringBuilder();
            sb.append("═══ ").append(Colors.underline("ECTester version:")).append(" ").append(ECTesterStandalone.VERSION).append(System.lineSeparator());
            sb.append("═══ ").append(Colors.underline("Library:")).append(" ").append(standaloneSuite.getLibrary().name()).append(System.lineSeparator());
            return sb.toString();
        }
        return "";
    }
}