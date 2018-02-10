package cz.crcs.ectester.common.test;

/**
 * @param <T>
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class SimpleTest<T extends BaseTestable> extends Test {
    protected T testable;
    protected TestCallback<T> callback;

    public SimpleTest(T testable, TestCallback<T> callback) {
        this.testable = testable;
        this.callback = callback;
    }

    public T getTestable() {
        return testable;
    }

    @Override
    protected void runSelf() {
        testable.run();
        result = callback.apply(testable);
    }
}
