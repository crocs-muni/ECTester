package cz.crcs.ectester.common.test;

import static cz.crcs.ectester.common.test.Result.Value;

/**
 * An abstract test that can be run and has a Result.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Test {
    protected boolean hasRun = false;
    protected Result result;

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

    public abstract String getDescription();

    public boolean hasRun() {
        return hasRun;
    }

    public abstract void run() throws TestException;

}
