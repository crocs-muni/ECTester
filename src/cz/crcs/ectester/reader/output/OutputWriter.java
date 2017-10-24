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
    void outputResponse(Response r);
    void outputTest(Test t);
    void end();
}
