package cz.crcs.ectester.common.test;

/**
 * @param <T>
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class SimpleTest<T extends BaseTestable> extends Test implements Testable {
    protected T testable;
    protected TestCallback<T> callback;

    public SimpleTest(T testable, TestCallback<T> callback) {
        if (testable == null) {
            throw new IllegalArgumentException("testable is null.");
        }
        if (callback == null) {
            throw new IllegalArgumentException("callback is null.");
        }
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

    @Override
    public SimpleTest clone() throws CloneNotSupportedException {
        SimpleTest clone = (SimpleTest) super.clone();
        clone.testable = testable.clone();
        return clone;
    }
}
