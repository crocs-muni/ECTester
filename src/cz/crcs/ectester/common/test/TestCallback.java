package cz.crcs.ectester.common.test;

import java.util.function.Function;

/**
 * @param <T>
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestCallback<T extends Testable> implements Function<T, Result> {

}
