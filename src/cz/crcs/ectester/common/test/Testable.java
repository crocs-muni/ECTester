package cz.crcs.ectester.common.test;

import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface Testable {

    /**
     * @return Whether this testable was run.
     */
    boolean hasRun();

    /**
     * Run this Testable.
     *
     * @throws TestException
     */
    void run() throws TestException;

    /**
     * @return Whether this Testable was OK.
     */
    boolean ok();

    /**
     * @return Whether an error happened.
     */
    boolean error();

    /**
     * Get the metadata of this Testable.
     *
     * @return The metadata of the testable.
     */
    Map<String, Object> meta();
}
