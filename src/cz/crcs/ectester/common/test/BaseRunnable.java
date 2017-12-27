package cz.crcs.ectester.common.test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class BaseRunnable implements Runnable {
    private boolean hasRun = false;
    private Func runImplicit;

    public BaseRunnable(Func runImplicit) {
        this.runImplicit = runImplicit;
    }

    @Override
    public boolean hasRun() {
        return hasRun;
    }

    @Override
    public void run() throws TestException {
        if (!hasRun) {
            runImplicit.run();
        }
        hasRun = true;
    }

    @FunctionalInterface
    public interface Func {
        void run() throws TestException;
    }
}
