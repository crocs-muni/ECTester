package cz.crcs.ectester.common.test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseTestable implements Testable {
    protected boolean hasRun;
    protected boolean ok;
    protected boolean error;
    protected Object errorCause;

    @Override
    public boolean hasRun() {
        return hasRun;
    }

    @Override
    public boolean ok() {
        return ok;
    }

    @Override
    public boolean error() {
        return error;
    }

    @Override
    public Object errorCause() {
        return errorCause;
    }

    @Override
    public void reset() {
        hasRun = false;
        ok = false;
        error = false;
        errorCause = null;
    }
}
