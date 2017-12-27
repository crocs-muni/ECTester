package cz.crcs.ectester.standalone.output;

import cz.crcs.ectester.common.output.BaseXMLTestWriter;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.standalone.test.KeyAgreementTestable;
import cz.crcs.ectester.standalone.test.KeyGeneratorTestable;
import cz.crcs.ectester.standalone.test.SignatureTestable;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class XMLTestWriter extends BaseXMLTestWriter {

    public XMLTestWriter(OutputStream output) throws ParserConfigurationException {
        super(output);
    }

    private Element kaElement(KeyAgreementTestable kat) {
        Element katElem = doc.createElement("key-agreement");

        Element secret = doc.createElement("secret");
        secret.setTextContent(ByteUtil.bytesToHex(kat.getSecret()));
        katElem.appendChild(secret);

        return katElem;
    }

    private Element kgtElement(KeyGeneratorTestable kgt) {
        Element kgtElem = doc.createElement("key-pair-generator");

        Element keyPair = doc.createElement("key-pair");
        Element pubkey = doc.createElement("pubkey");
        PublicKey pkey = kgt.getKeyPair().getPublic();
        pubkey.setAttribute("algorithm", pkey.getAlgorithm());
        pubkey.setAttribute("format", pkey.getFormat());
        pubkey.setTextContent(ByteUtil.bytesToHex(pkey.getEncoded()));
        keyPair.appendChild(pubkey);

        Element privkey = doc.createElement("privkey");
        PrivateKey skey = kgt.getKeyPair().getPrivate();
        privkey.setAttribute("algorithm", skey.getAlgorithm());
        privkey.setAttribute("format", skey.getFormat());
        privkey.setTextContent(ByteUtil.bytesToHex(skey.getEncoded()));
        keyPair.appendChild(privkey);

        return kgtElem;
    }

    private Element sigElement(SignatureTestable sig) {
        Element sigElem = doc.createElement("signature");
        sigElem.setAttribute("verified", sig.getVerified() ? "true" : "false");

        Element raw = doc.createElement("raw");
        raw.setTextContent(ByteUtil.bytesToHex(sig.getSignature()));
        sigElem.appendChild(raw);

        return sigElem;
    }

    @Override
    protected Element testableElement(Testable t) {
        Element result = doc.createElement("test");
        if (t instanceof KeyGeneratorTestable) {
            result.setAttribute("type", "key-pair-generator");
            result.appendChild(kgtElement((KeyGeneratorTestable) t));
        } else if (t instanceof KeyAgreementTestable) {
            result.setAttribute("type", "key-agreement");
            result.appendChild(kaElement((KeyAgreementTestable) t));
        } else if (t instanceof SignatureTestable) {
            result.setAttribute("type", "signature");
            result.appendChild(sigElement((SignatureTestable) t));
        }
        return result;
    }
}
