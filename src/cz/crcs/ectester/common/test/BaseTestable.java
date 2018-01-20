package cz.crcs.ectester.common.test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseTestable implements Testable {
    protected boolean hasRun;
    protected boolean ok;
    protected boolean error;

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
    public void reset() {
        hasRun = false;
        ok = false;
        error = false;
    }
}
