package cz.crcs.ectester.common.test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface Testable extends Runnable {
    /**
     * @return Whether this Testable was OK.
     */
    boolean ok();

    /**
     * @return Whether an error happened.
     */
    boolean error();
}
