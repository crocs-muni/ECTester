package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.reader.test.CommandTest;
import cz.crcs.ectester.reader.test.CardTestSuite;
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
public class XMLTestWriter implements TestWriter {
    private OutputStream output;
    private DocumentBuilder db;
    private Document doc;
    private Node root;

    public XMLTestWriter(OutputStream output) throws ParserConfigurationException {
        this.output = output;
        this.db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }

    @Override
    public void begin(CardTestSuite suite) {
        doc = db.newDocument();
        Element rootElem = doc.createElement("testSuite");
        rootElem.setAttribute("name", suite.getName());
        rootElem.setAttribute("desc", suite.getDescription());

        root = rootElem;
        doc.appendChild(root);
    }

    private Element commandElement(Command c) {
        Element commandElem = doc.createElement("command");

        Element apdu = doc.createElement("apdu");
        apdu.setTextContent(ByteUtil.bytesToHex(c.getAPDU().getBytes()));
        commandElem.appendChild(apdu);

        return commandElem;
    }

    private Element responseElement(Response r) {
        Element responseElem = doc.createElement("response");
        responseElem.setAttribute("successful", r.successful() ? "true" : "false");

        Element apdu = doc.createElement("apdu");
        apdu.setTextContent(ByteUtil.bytesToHex(r.getAPDU().getBytes()));
        responseElem.appendChild(apdu);

        Element naturalSW = doc.createElement("natural-sw");
        naturalSW.setTextContent(String.valueOf(Short.toUnsignedInt(r.getNaturalSW())));
        responseElem.appendChild(naturalSW);

        Element sws = doc.createElement("sws");
        for (int i = 0; i < r.getNumSW(); ++i) {
            Element sw = doc.createElement("sw");
            sw.setTextContent(String.valueOf(Short.toUnsignedInt(r.getSW(i))));
            sws.appendChild(sw);
        }
        responseElem.appendChild(sws);

        Element duration = doc.createElement("duration");
        duration.setTextContent(String.valueOf(r.getDuration()));
        responseElem.appendChild(duration);

        Element description = doc.createElement("desc");
        description.setTextContent(r.getDescription());
        responseElem.appendChild(description);

        return responseElem;
    }

    private Element testElement(Test t) {
        Element testElem = doc.createElement("test");

        if (t instanceof CommandTest) {
            CommandTest test = (CommandTest) t;
            testElem.setAttribute("type", "simple");
            testElem.appendChild(commandElement(test.getCommand()));
            testElem.appendChild(responseElement(test.getResponse()));
        } else if (t instanceof CompoundTest) {
            CompoundTest test = (CompoundTest) t;
            testElem.setAttribute("type", "compound");
            for (Test innerTest : test.getTests()) {
                testElem.appendChild(testElement(innerTest));
            }
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