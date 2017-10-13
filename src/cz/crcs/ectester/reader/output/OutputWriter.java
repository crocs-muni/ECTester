package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.Test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface OutputWriter {
    void begin();
    void printResponse(Response r);
    void printTest(Test t);
    void end();
}
