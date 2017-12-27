package cz.crcs.ectester.common.test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface Runnable {
    /**
     * @return Whether this runnable was run.
     */
    boolean hasRun();

    /**
     * Run this Runnable.
     *
     * @throws TestException
     */
    void run() throws TestException;
}
