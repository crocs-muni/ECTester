package cz.crcs.ectester.standalone.test.base;

import cz.crcs.ectester.common.test.BaseTestable;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class StandaloneTestable<T extends Enum<T>> extends BaseTestable {
    protected T stage;

    public T getStage() {
        return stage;
    }
}
