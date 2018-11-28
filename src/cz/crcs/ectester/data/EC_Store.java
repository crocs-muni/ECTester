package cz.crcs.ectester.data;

import cz.crcs.ectester.common.ec.*;
import javacard.security.KeyPair;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.ext.EntityResolver2;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.function.Function;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Store {
    private DocumentBuilder db;
    private Map<String, EC_Category> categories;
    private static EC_Store instance;

    private EC_Store() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        try {
            SchemaFactory scf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema sch = scf.newSchema(this.getClass().getResource("/cz/crcs/ectester/data/schema.xsd"));
            dbf.setSchema(sch);
            dbf.setNamespaceAware(true);
            dbf.setIgnoringComments(true);
            dbf.setXIncludeAware(true);
            dbf.setIgnoringElementContentWhitespace(true);
            db = dbf.newDocumentBuilder();
            db.setErrorHandler(new ErrorHandler() {
                @Override
                public void warning(SAXParseException exception) throws SAXException {
                    System.err.println("EC_Store | Warning : " + exception);
                }

                @Override
                public void error(SAXParseException exception) throws SAXException {
                    System.err.println("EC_Store | Error : " + exception);
                }

                @Override
                public void fatalError(SAXParseException exception) throws SAXException {
                    System.err.println("EC_Store | Fatal : " + exception);
                    throw new SAXException(exception);
                }
            });
            db.setEntityResolver(new EntityResolver2() {
                @Override
                public InputSource getExternalSubset(String name, String baseURI) throws SAXException, IOException {
                    return null;
                }

                @Override
                public InputSource resolveEntity(String name, String publicId, String baseURI, String systemId) throws SAXException, IOException {
                    InputSource is = new InputSource();
                    is.setSystemId(systemId);
                    is.setByteStream(getClass().getClass().getResourceAsStream("/cz/crcs/ectester/data/" + systemId));
                    return is;
                }

                @Override
                public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException {
                    return null;
                }
            });

            parse();
        } catch (ParserConfigurationException | SAXException | IOException e) {
            e.printStackTrace();
        }
    }

    private void parse() throws SAXException, ParserConfigurationException, IOException {

        InputStream categories = this.getClass().getResourceAsStream("/cz/crcs/ectester/data/categories.xml");
        if (categories == null) {
            throw new IOException();
        }
        Document categoriesDoc = db.parse(categories);
        categories.close();
        categoriesDoc.normalize();

        NodeList catList = categoriesDoc.getElementsByTagName("category");

        this.categories = new TreeMap<>();
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

        Map<String, EC_Data> objMap = new TreeMap<>();

        InputStream curves = this.getClass().getResourceAsStream("/cz/crcs/ectester/data/" + dir + "/curves.xml");
        if (curves != null) {
            Document curvesDoc = db.parse(curves);
            curvesDoc.normalize();

            NodeList curveList = curvesDoc.getElementsByTagName("curve");

            for (int i = 0; i < curveList.getLength(); ++i) {
                Node curveNode = curveList.item(i);
                if (curveNode instanceof Element) {
                    Element curveElem = (Element) curveNode;
                    Node id = curveElem.getElementsByTagName("id").item(0);
                    Node bits = curveElem.getElementsByTagName("bits").item(0);
                    Node field = curveElem.getElementsByTagName("field").item(0);

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

                    EC_Curve curve = new EC_Curve(id.getTextContent(), bitsize, alg, descs);

                    InputStream csv = parseDataElement(dir, curveElem);
                    if (!curve.readCSV(csv)) {
                        throw new IOException("Invalid csv data." + id.getTextContent());
                    }
                    csv.close();

                    objMap.put(id.getTextContent(), curve);
                } else {
                    throw new SAXException("?");
                }
            }
            curves.close();
        }

        InputStream keys = this.getClass().getResourceAsStream("/cz/crcs/ectester/data/" + dir + "/keys.xml");
        if (keys != null) {
            Document keysDoc = db.parse(keys);
            keysDoc.normalize();

            NodeList directs = keysDoc.getDocumentElement().getChildNodes();
            for (int i = 0; i < directs.getLength(); ++i) {
                Node direct = directs.item(i);
                if (direct instanceof Element) {
                    Element elem = (Element) direct;

                    NodeList ids = elem.getElementsByTagName("id");
                    if (ids.getLength() != 1) {
                        throw new SAXException("key no id?");
                    }
                    String id = ids.item(0).getTextContent();

                    EC_Params result = parseKeylike(dir, elem);

                    objMap.put(id, result);
                } else {
                    throw new SAXException("?");
                }
            }
            keys.close();
        }

        InputStream results = this.getClass().getResourceAsStream("/cz/crcs/ectester/data/" + dir + "/results.xml");
        if (results != null) {
            Document resultsDoc = db.parse(results);
            resultsDoc.normalize();

            NodeList directs = resultsDoc.getDocumentElement().getChildNodes();
            for (int i = 0; i < directs.getLength(); ++i) {
                Node direct = directs.item(i);
                if (direct instanceof Element) {
                    Element elem = (Element) direct;

                    NodeList ids = elem.getElementsByTagName("id");
                    if (ids.getLength() != 1) {
                        throw new SAXException("result no id?");
                    }
                    String id = ids.item(0).getTextContent();

                    EC_Data result = parseResultlike(dir, elem);

                    objMap.put(id, result);
                } else {
                    throw new SAXException("?");
                }
            }
            results.close();
        }

        return new EC_Category(name, dir, desc, objMap);
    }

    private EC_Data parseResultlike(String dir, Element elem) throws SAXException, IOException {
        String tag = elem.getTagName();
        Node id = elem.getElementsByTagName("id").item(0);

        NodeList descc = elem.getElementsByTagName("desc");
        String descs = null;
        if (descc.getLength() != 0) {
            descs = descc.item(0).getTextContent();
        }

        Node curve = elem.getElementsByTagName("curve").item(0);

        EC_Data result;
        if (tag.equals("kaResult")) {
            Node ka = elem.getElementsByTagName("ka").item(0);
            Node onekey = elem.getElementsByTagName("onekey").item(0);
            Node otherkey = elem.getElementsByTagName("otherkey").item(0);

            result = new EC_KAResult(id.getTextContent(), ka.getTextContent(), curve.getTextContent(), onekey.getTextContent(), otherkey.getTextContent(), descs);
        } else if (tag.equals("sigResult")) {
            Node sig = elem.getElementsByTagName("sig").item(0);
            Node signkey = elem.getElementsByTagName("signkey").item(0);
            Node verifykey = elem.getElementsByTagName("verifykey").item(0);
            NodeList datas = elem.getElementsByTagName("raw");
            String data = null;
            if (datas.getLength() != 0) {
                data = datas.item(0).getTextContent();
            }

            result = new EC_SigResult(id.getTextContent(), sig.getTextContent(), curve.getTextContent(), signkey.getTextContent(), verifykey.getTextContent(), data, descs);
        } else {
            throw new SAXException("?");
        }

        InputStream csv = parseDataElement(dir, elem);
        if (!result.readCSV(csv)) {
            throw new IOException("Invalid csv data. " + id.getTextContent());
        }
        csv.close();

        return result;
    }

    private EC_Params parseKeylike(String dir, Element elem) throws SAXException, IOException {
        Node id = elem.getElementsByTagName("id").item(0);
        Node curve = elem.getElementsByTagName("curve").item(0);

        NodeList desc = elem.getElementsByTagName("desc");
        String descs = null;
        if (desc.getLength() != 0) {
            descs = desc.item(0).getTextContent();
        }

        EC_Params result;
        if (elem.getTagName().equals("pubkey")) {
            result = new EC_Key.Public(id.getTextContent(), curve.getTextContent(), descs);
        } else if (elem.getTagName().equals("privkey")) {
            result = new EC_Key.Private(id.getTextContent(), curve.getTextContent(), descs);
        } else if (elem.getTagName().equals("keypair")) {
            result = new EC_Keypair(id.getTextContent(), curve.getTextContent(), descs);
        } else {
            throw new SAXException("?");
        }

        InputStream csv = parseDataElement(dir, elem);
        if (!result.readCSV(csv)) {
            throw new IOException("Invalid CSV data. " + id.getTextContent());
        }
        csv.close();

        return result;
    }

    private InputStream parseDataElement(String dir, Element elem) throws SAXException {
        NodeList file = elem.getElementsByTagName("file");
        NodeList inline = elem.getElementsByTagName("inline");

        InputStream csv;
        if (file.getLength() == 1) {
            csv = this.getClass().getResourceAsStream("/cz/crcs/ectester/data/" + dir + "/" + file.item(0).getTextContent());
        } else if (inline.getLength() == 1) {
            csv = new ByteArrayInputStream(inline.item(0).getTextContent().getBytes());
        } else {
            throw new SAXException("?");
        }
        return csv;
    }

    public Map<String, EC_Category> getCategories() {
        return Collections.unmodifiableMap(categories);
    }

    public EC_Category getCategory(String category) {
        return categories.get(category);
    }

    public Map<String, EC_Data> getObjects(String category) {
        EC_Category cat = categories.get(category);
        if (cat != null) {
            return cat.getObjects();
        }
        return null;
    }

    public <T extends EC_Data> Map<String, T> getObjects(Class<T> objClass, String category) {
        EC_Category cat = categories.get(category);
        if (cat != null) {
            return cat.getObjects(objClass);
        }
        return null;
    }

    public <T extends EC_Data> T getObject(Class<T> objClass, String category, String id) {
        EC_Category cat = categories.get(category);
        if (cat != null) {
            return cat.getObject(objClass, id);
        }
        return null;
    }

    public <T extends EC_Data> T getObject(Class<T> objClass, String query) {
        int split = query.indexOf("/");
        if (split < 0) {
            return null;
        }
        return getObject(objClass, query.substring(0, split), query.substring(split + 1));
    }

    private static <T extends EC_Data> Map<EC_Curve, List<T>> mapKeyToCurve(Collection<T> data, Function<T, String> getter) {
        Map<EC_Curve, List<T>> curves = new TreeMap<>();
        for (T item : data) {
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, getter.apply(item));
            List<T> curveKeys = curves.getOrDefault(curve, new LinkedList<>());
            curveKeys.add(item);
            curves.putIfAbsent(curve, curveKeys);
        }
        for (List<T> keyList : curves.values()) {
            Collections.sort(keyList);
        }
        return curves;
    }

    public static <T extends EC_Key> Map<EC_Curve, List<T>> mapKeyToCurve(Collection<T> keys) {
        return mapKeyToCurve(keys, EC_Key::getCurve);
    }

    public static Map<EC_Curve, List<EC_KAResult>> mapResultToCurve(Collection<EC_KAResult> results) {
        return mapKeyToCurve(results, EC_KAResult::getCurve);
    }

    public static <T extends EC_Data> Map<String, List<T>> mapToPrefix(Collection<T> data) {
        Map<String, List<T>> groups = new TreeMap<>();
        for (T item : data) {
            String prefix = item.getId().split("/")[0];
            List<T> group = groups.getOrDefault(prefix, new LinkedList<>());
            group.add(item);
            groups.putIfAbsent(prefix, group);
        }
        for (List<T> itemList : groups.values()) {
            Collections.sort(itemList);
        }
        return groups;
    }

    public static EC_Store getInstance() {
        if (instance == null) {
            instance = new EC_Store();
        }
        return instance;
    }

}
