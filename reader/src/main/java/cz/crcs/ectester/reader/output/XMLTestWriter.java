package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.output.BaseXMLTestWriter;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.CardTestSuite;
import cz.crcs.ectester.reader.test.CommandTestable;
import org.w3c.dom.Element;

import javax.smartcardio.CardException;
import javax.xml.parsers.ParserConfigurationException;
import java.io.OutputStream;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class XMLTestWriter extends BaseXMLTestWriter {
    public XMLTestWriter(OutputStream output) throws ParserConfigurationException {
        super(output);
    }

    private Element commandElement(Command c) {
        Element commandElem = doc.createElement("command");
        if (c == null) {
            return commandElem;
        }

        Element apdu = doc.createElement("apdu");
        apdu.setTextContent(ByteUtil.bytesToHex(c.getAPDU().getBytes()));
        commandElem.appendChild(apdu);

        Element description = doc.createElement("desc");
        description.setTextContent(c.getDescription());
        commandElem.appendChild(description);

        return commandElem;
    }

    private Element responseElement(Response r) {
        Element responseElem = doc.createElement("response");
        if (r == null) {
            return responseElem;
        }

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

    private Element cplcElement(CardMngr card) {
        Element result = doc.createElement("cplc");
        try {
            CardMngr.CPLC cplc = card.getCPLC();
            if (!cplc.values().isEmpty()) {
                for (Map.Entry<CardMngr.CPLC.Field, byte[]> entry : cplc.values().entrySet()) {
                    CardMngr.CPLC.Field field = entry.getKey();
                    byte[] value = entry.getValue();
                    Element keyVal = doc.createElement(field.name());
                    keyVal.setTextContent(ByteUtil.bytesToHex(value, false));
                    result.appendChild(keyVal);
                }
            }
        } catch (CardException ignored) {
        }
        return result;
    }

    private Element appletElement(CardMngr card) {
        Element result = doc.createElement("applet");
        try {
            Response.GetInfo info = new Command.GetInfo(card).send();
            result.setAttribute("version", info.getVersion());
            result.setAttribute("javacard", String.format("%.1f", info.getJavaCardVersion()));
            result.setAttribute("base", String.format("%#x", info.getBase()));
            result.setAttribute("cleanup", String.valueOf(info.getCleanupSupport()));
            Element arrays = doc.createElement("arrays");
            Element apduBuf = doc.createElement("length");
            apduBuf.setAttribute("name", "apduBuf");
            apduBuf.setTextContent(String.valueOf(info.getApduBufferLength()));
            Element ramArray = doc.createElement("length");
            ramArray.setAttribute("name", "ramArray");
            ramArray.setTextContent(String.valueOf(info.getRamArrayLength()));
            Element ramArray2 = doc.createElement("length");
            ramArray2.setAttribute("name", "ramArray2");
            ramArray2.setTextContent(String.valueOf(info.getRamArray2Length()));
            Element apduArray = doc.createElement("length");
            apduArray.setAttribute("name", "apduArray");
            apduArray.setTextContent(String.valueOf(info.getApduArrayLength()));
            arrays.appendChild(apduBuf);
            arrays.appendChild(ramArray);
            arrays.appendChild(ramArray2);
            arrays.appendChild(apduArray);
            result.appendChild(arrays);
        } catch (CardException ignored) {
        }
        return result;
    }

    @Override
    protected Element deviceElement(TestSuite suite) {
        if (suite instanceof CardTestSuite) {
            CardTestSuite cardSuite = (CardTestSuite) suite;
            Element result = doc.createElement("device");
            result.setAttribute("type", "card");
            result.setAttribute("ectester", ECTesterReader.VERSION + ECTesterReader.GIT_COMMIT);
            result.appendChild(cplcElement(cardSuite.getCard()));
            result.appendChild(appletElement(cardSuite.getCard()));

            Element atr = doc.createElement("ATR");
            atr.setTextContent(ByteUtil.bytesToHex(cardSuite.getCard().getATR().getBytes(), false));
            result.appendChild(atr);
            return result;
        }
        return null;
    }
}