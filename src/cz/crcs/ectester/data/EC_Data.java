package cz.crcs.ectester.data;

import cz.crcs.ectester.reader.ec.EC_Curve;
import cz.crcs.ectester.reader.ec.EC_Key;
import cz.crcs.ectester.reader.ec.EC_Keypair;
import cz.crcs.ectester.reader.ec.EC_Params;
import javacard.security.KeyPair;
import org.omg.PortableInterceptor.SYSTEM_EXCEPTION;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Data {

    private DocumentBuilderFactory dbf;

    private Map<String, EC_Category> categories;

    public EC_Data() {
        dbf = DocumentBuilderFactory.newInstance();

        try {
            SchemaFactory scf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema sch = scf.newSchema(this.getClass().getResource("/cz/crcs/ectester/data/schema.xsd"));
            dbf.setSchema(sch);
            dbf.setNamespaceAware(true);
            dbf.setIgnoringComments(true);
            dbf.setIgnoringElementContentWhitespace(true);

            parse();
        } catch (ParserConfigurationException | IOException | SAXException e) {
            e.printStackTrace();
        }
    }

    private void parse() throws SAXException, ParserConfigurationException, IOException {
        DocumentBuilder db = dbf.newDocumentBuilder();

        Document categoriesDoc = db.parse(this.getClass().getResourceAsStream("/cz/crcs/ectester/data/categories.xml"));
        categoriesDoc.normalize();

        NodeList catList = categoriesDoc.getElementsByTagName("category");

        this.categories = new HashMap<>(catList.getLength());
        for (int i = 0; i < catList.getLength(); ++i) {
            Node catNode = catList.item(i);
            if (catNode instanceof Element) {
                Element catElem = (Element) catNode;
                Node name = catElem.getElementsByTagName("name").item(0);
                Node dir = catElem.getElementsByTagName("directory").item(0);
                Node desc = catElem.getElementsByTagName("desc").item(0);

                EC_Category category = parseCategory(name.getTextContent(), dir.getTextContent(), desc.getTextContent());
                this.categories.put(name.getTextContent(), category);
            } else {
                throw new SAXException("?");
            }
        }
    }

    private EC_Category parseCategory(String name, String dir, String desc) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilder db = dbf.newDocumentBuilder();

        Map<String, EC_Params> objMap = new HashMap<>();

        InputStream curvesStream = this.getClass().getResourceAsStream("/cz/crcs/ectester/data/" + dir + "/curves.xml");
        if (curvesStream != null) {
            Document curvesDoc = db.parse(curvesStream);
            curvesDoc.normalize();

            NodeList curveList = curvesDoc.getElementsByTagName("curve");

            for (int i = 0; i < curveList.getLength(); ++i) {
                Node curveNode = curveList.item(i);
                if (curveNode instanceof Element) {
                    Element curveElem = (Element) curveNode;
                    Node id = curveElem.getElementsByTagName("id").item(0);
                    Node bits = curveElem.getElementsByTagName("bits").item(0);
                    Node field = curveElem.getElementsByTagName("field").item(0);
                    Node file = curveElem.getElementsByTagName("file").item(0);

                    NodeList descc = curveElem.getElementsByTagName("desc");
                    String descs = null;
                    if (descc.getLength() != 0) {
                        descs = descc.item(0).getTextContent();
                    }

                    byte alg;
                    if (field.getTextContent().equalsIgnoreCase("prime")) {
                        alg = KeyPair.ALG_EC_FP;
                    } else {
                        alg = KeyPair.ALG_EC_F2M;
                    }
                    short bitsize = Short.parseShort(bits.getTextContent());

                    EC_Curve curve = new EC_Curve(bitsize, alg, descs);
                    if (!curve.readCSV(this.getClass().getResourceAsStream("/cz/crcs/ectester/data/" + dir + "/" + file.getTextContent()))) {
                        throw new IOException("Invalid csv data.");
                    }

                    objMap.put(id.getTextContent(), curve);
                } else {
                    throw new SAXException("?");
                }
            }
        }

        InputStream keysStream = this.getClass().getResourceAsStream("/cz/crcs/ectester/data" + dir + "/keys.xml");
        if (keysStream != null) {
            Document keysDoc = db.parse(keysStream);
            keysDoc.normalize();

            NodeList directs = keysDoc.getDocumentElement().getChildNodes();
            for (int i = 0; i < directs.getLength(); ++i) {
                Node direct = directs.item(i);
                if (direct instanceof Element) {
                    Element elem = (Element) direct;
                    String tag = elem.getTagName();

                    NodeList childs = elem.getChildNodes();
                    String id = null;
                    for (int j = 0; j < childs.getLength(); ++j) {
                        Node child = childs.item(j);
                        if (child instanceof Element) {
                            Element childElem = (Element) child;
                            if (childElem.getTagName().equals("id")) {
                                id = childElem.getTextContent();
                                break;
                            }
                        }
                    }
                    if (id == null) {
                        throw new SAXException("key no id?");
                    }

                    EC_Params result = parseKeylike(dir, elem);

                    objMap.put(id, result);
                } else {
                    throw new SAXException("?");
                }
            }
        }

        return new EC_Category(name, dir, desc, objMap);
    }

    private EC_Params parseKeylike(String dir, Element elem) throws SAXException {
        Node file = elem.getElementsByTagName("file").item(0);
        Node curve = elem.getElementsByTagName("curve").item(0);

        NodeList desc = elem.getElementsByTagName("desc");
        String descs = null;
        if (desc.getLength() != 0) {
            descs = desc.item(0).getTextContent();
        }

        EC_Params result;
        if (elem.getTagName().equals("pubkey")) {
            result = new EC_Key.Public(curve.getTextContent(), descs);
        } else if (elem.getTagName().equals("privkey")) {
            result = new EC_Key.Private(curve.getTextContent(), descs);
        } else if (elem.getTagName().equals("keypair")) {
            result = new EC_Keypair(curve.getTextContent(), descs);
        } else {
            throw new SAXException("?");
        }
        result.readCSV(this.getClass().getResourceAsStream("/cz/crcs/ectester/data/" + dir + "/" + file.getTextContent()));
        return result;
    }

    public Map<String, EC_Category> getCategories() {
        return Collections.unmodifiableMap(categories);
    }

    public EC_Category getCategory(String category) {
        return categories.get(category);
    }

    public Map<String, EC_Params> getObjects(String category) {
        EC_Category cat = categories.get(category);
        if (cat != null) {
            return cat.getObjects();
        }
        return null;
    }

    public <T extends EC_Params> Map<String, T> getObjects(Class<T> objClass, String category) {
        EC_Category cat = categories.get(category);
        if (cat != null) {
            return cat.getObjects(objClass);
        }
        return null;
    }

    public <T extends EC_Params> T getObject(Class<T> objClass, String category, String id) {
        EC_Category cat = categories.get(category);
        if (cat != null) {
            return cat.getObject(objClass, id);
        }
        return null;
    }

    public <T extends EC_Params> T getObject(Class<T> objClass, String query) {
        String[] parts = query.split("/");
        if (parts.length != 2) {
            return null;
        }
        return getObject(objClass, parts[0], parts[1]);
    }


}
