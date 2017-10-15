package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.Test;

import javax.xml.stream.XMLStreamException;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface OutputWriter {
    void begin();
    void printResponse(Response r);
    void printTest(Test t);
    void end();
}
