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
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseXMLTestWriter implements TestWriter {
    private OutputStream output;
    private DocumentBuilder db;
    protected Document doc;
    private Node root;
    private Node tests;

    public BaseXMLTestWriter(OutputStream output) throws ParserConfigurationException {
        this.output = output;
        this.db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }

    @Override
    public void begin(TestSuite suite) {
        doc = db.newDocument();
        Element rootElem = doc.createElement("testSuite");
        rootElem.setAttribute("name", suite.getName());
        rootElem.setAttribute("desc", suite.getTextDescription());
        DateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
        Date date = new Date();
        rootElem.setAttribute("date", dateFormat.format(date));

        root = rootElem;
        doc.appendChild(root);
        root.appendChild(deviceElement(suite));
        tests = doc.createElement("tests");
        root.appendChild(tests);
    }

    protected abstract Element testableElement(Testable t);

    protected abstract Element deviceElement(TestSuite suite);

    private String causeString(Object cause) {
        if (cause == null) {
            return "null";
        } else if (cause instanceof Throwable) {
            StringBuilder sb = new StringBuilder();
            for (Throwable t = (Throwable) cause; t != null; t = t.getCause()) {
                sb.append(t.toString());
                sb.append(System.lineSeparator());
            }
            return sb.toString();
        } else {
            return cause.toString();
        }
    }

    private Element resultElement(Result result) {
        Element resultElem = doc.createElement("result");

        Element ok = doc.createElement("ok");
        ok.setTextContent(String.valueOf(result.ok()));
        Element value = doc.createElement("value");
        value.setTextContent(result.getValue().name());
        Element cause = doc.createElement("cause");
        cause.setTextContent(causeString(result.getCause()));

        resultElem.appendChild(ok);
        resultElem.appendChild(value);
        resultElem.appendChild(cause);

        return resultElem;
    }

    private Element testElement(Test t, int index) {
        Element testElem;
        if (t instanceof CompoundTest) {
            CompoundTest test = (CompoundTest) t;
            testElem = doc.createElement("test");
            testElem.setAttribute("type", "compound");
            for (Test innerTest : test.getStartedTests()) {
                testElem.appendChild(testElement(innerTest, -1));
            }
        } else {
            SimpleTest<? extends BaseTestable> test = (SimpleTest<? extends BaseTestable>) t;
            testElem = testableElement(test.getTestable());
        }

        Element description = doc.createElement("desc");
        description.setTextContent(t.getDescription());
        testElem.appendChild(description);

        Element result = resultElement(t.getResult());
        testElem.appendChild(result);

        if (index != -1) {
            testElem.setAttribute("index", String.valueOf(index));
        }

        return testElem;
    }

    @Override
    public void outputTest(Test t, int index) {
        if (!t.hasRun())
            return;
        tests.appendChild(testElement(t, index));
    }

    @Override
    public void outputError(Test t, Throwable cause, int index) {
        tests.appendChild(testElement(t, index));
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
