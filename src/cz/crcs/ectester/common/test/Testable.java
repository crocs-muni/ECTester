package cz.crcs.ectester.common.test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface Testable {

    boolean hasRun();

    void run() throws TestException;

    boolean ok();

    boolean error();
}
