package cz.crcs.ectester.common.test;

import static cz.crcs.ectester.common.test.Result.Value;

/**
 * An abstract test that can be run and has a Result.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Test implements Testable, Cloneable {
    protected boolean hasRun;
    protected boolean hasStarted;
    protected Result result;

    public Result getResult() {
        return result;
    }

    public boolean ok() {
        if (result == null) {
            return true;
        }
        return result.ok();
    }

    @Override
    public boolean error() {
        if (result == null) {
            return false;
        }
        return result.compareTo(Value.ERROR);
    }

    @Override
    public Object errorCause() {
        if (result == null || !result.compareTo(Value.ERROR)) {
            return null;
        }
        return result.getCause();
    }

    @Override
    public boolean hasRun() {
        return hasRun;
    }

    public boolean hasStarted() {
        return hasStarted;
    }

    @Override
    public void reset() {
        hasRun = false;
        hasStarted = false;
        result = null;
    }

    public abstract String getDescription();

    @Override
    public Test clone() throws CloneNotSupportedException {
        return (Test) super.clone();
    }

    @Override
    public void run() {
        if (hasRun)
            return;
        try {
            hasStarted = true;
            runSelf();
            hasRun = true;
        } catch (TestException e) {
            result = new Result(Value.ERROR, e);
            throw e;
        } catch (Exception e) {
            result = new Result(Value.ERROR, e);
            throw new TestException(e);
        }
    }

    protected abstract void runSelf();
}
