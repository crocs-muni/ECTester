package cz.crcs.ectester.standalone.test.base;

import cz.crcs.ectester.common.test.BaseTestable;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class StandaloneTestable<T extends Enum<T>> extends BaseTestable {
    protected T stage;
    protected Exception exception;

    public T getStage() {
        return stage;
    }

    public Exception getException() {
        return exception;
    }

    protected void failOnException(Exception ex) {
        ok = false;
        hasRun = true;
        exception = ex;
    }
}
