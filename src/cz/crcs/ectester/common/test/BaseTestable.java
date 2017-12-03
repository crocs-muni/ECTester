package cz.crcs.ectester.common.test;

import java.util.Collections;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseTestable implements Testable {
    protected boolean hasRun;
    protected boolean ok;
    protected boolean error;

    protected Map<String, Object> meta;

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
    public Map<String, Object> meta() {
        return Collections.unmodifiableMap(meta);
    }
}
