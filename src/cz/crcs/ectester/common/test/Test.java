package cz.crcs.ectester.common.test;

import java.util.Collections;
import java.util.Map;

import static cz.crcs.ectester.common.test.Result.Value;

/**
 * An abstract test that can be run and has a Result.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Test implements Testable {
    protected boolean hasRun;
    protected Result result;
    protected Map<String, Object> meta;

    public Result getResult() {
        if (!hasRun) {
            return null;
        }
        return result;
    }

    public Value getResultValue() {
        if (!hasRun) {
            return null;
        }
        return result.getValue();
    }

    public String getResultCause() {
        if (!hasRun) {
            return null;
        }
        return result.getCause();
    }

    public boolean ok() {
        if (!hasRun) {
            return true;
        }
        return result.ok();
    }

    @Override
    public boolean error() {
        if (!hasRun) {
            return false;
        }
        return result.compareTo(Value.ERROR);
    }

    @Override
    public boolean hasRun() {
        return hasRun;
    }

    @Override
    public Map<String, Object> meta() {
        return Collections.unmodifiableMap(meta);
    }

    public abstract String getDescription();

    @Override
    public abstract void run() throws TestException;

}
