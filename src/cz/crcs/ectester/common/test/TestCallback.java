package cz.crcs.ectester.common.test;

import java.util.function.Function;

/**
 *
 * @author Jan Jancar johny@neuromancer.sk
 * @param <T>
 */
public abstract class TestCallback<T extends Testable> implements Function<T, Result> {

}
