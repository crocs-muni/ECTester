package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.OutputStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseXMLTestWriter implements TestWriter {
    private OutputStream output;
    private DocumentBuilder db;
    protected Document doc;
    private Node root;

    public BaseXMLTestWriter(OutputStream output) throws ParserConfigurationException {
        this.output = output;
        this.db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }

    @Override
    public void begin(TestSuite suite) {
        doc = db.newDocument();
        Element rootElem = doc.createElement("testSuite");
        rootElem.setAttribute("name", suite.getName());
        rootElem.setAttribute("desc", suite.getDescription());

        root = rootElem;
        doc.appendChild(root);
        root.appendChild(deviceElement(suite));
    }

    protected abstract Element testableElement(Testable t);

    protected abstract Element deviceElement(TestSuite suite);

    private Element testElement(Test t) {
        Element testElem;
        if (t instanceof CompoundTest) {
            CompoundTest test = (CompoundTest) t;
            testElem = doc.createElement("test");
            testElem.setAttribute("type", "compound");
            for (Test innerTest : test.getTests()) {
                testElem.appendChild(testElement(innerTest));
            }
        } else {
            SimpleTest test = (SimpleTest) t;
            testElem = testableElement(test.getTestable());
        }

        Element description = doc.createElement("desc");
        description.setTextContent(t.getDescription());
        testElem.appendChild(description);

        Element result = doc.createElement("result");
        Element ok = doc.createElement("ok");
        ok.setTextContent(String.valueOf(t.ok()));
        Element value = doc.createElement("value");
        value.setTextContent(t.getResultValue().name());
        Element cause = doc.createElement("cause");
        cause.setTextContent(t.getResultCause());
        result.appendChild(ok);
        result.appendChild(value);
        result.appendChild(cause);
        testElem.appendChild(result);

        return testElem;
    }

    @Override
    public void outputTest(Test t) {
        if (!t.hasRun())
            return;
        root.appendChild(testElement(t));
    }

    @Override
    public void end() {
        try {
            DOMSource domSource = new DOMSource(doc);
            StreamResult result = new StreamResult(output);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            transformer.transform(domSource, result);
        } catch (TransformerException e) {
            e.printStackTrace();
        }
    }
}
