package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.output.BaseXMLTestWriter;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.CommandTestable;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;
import java.io.OutputStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class XMLTestWriter extends BaseXMLTestWriter {
    public XMLTestWriter(OutputStream output) throws ParserConfigurationException {
        super(output);
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

    @Override
    protected Element testableElement(Testable t) {
        if (t instanceof CommandTestable) {
            CommandTestable cmd = (CommandTestable) t;
            Element result = doc.createElement("test");
            result.setAttribute("type", "command");
            result.appendChild(commandElement(cmd.getCommand()));
            result.appendChild(responseElement(cmd.getResponse()));
            return result;
        }
        return null;
    }
}