package cz.crcs.ectester.common.test;

import java.util.function.Function;

/**
 *
 * @param <T>
 */
public abstract class TestCallback<T extends Testable> implements Function<T, Result> {

}
