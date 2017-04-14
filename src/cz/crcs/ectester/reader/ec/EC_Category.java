package cz.crcs.ectester.reader.ec;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Category {

    private String name;
    private String directory;
    private String desc;

    private Map<String, EC_Data> objects;


    public EC_Category(String name, String directory) {
        this.name = name;
        this.directory = directory;
    }

    public EC_Category(String name, String directory, String desc) {
        this(name, directory);
        this.desc = desc;
    }

    public EC_Category(String name, String directory, String desc, Map<String, EC_Data> objects) {
        this(name, directory, desc);
        this.objects = objects;
    }

    public String getName() {
        return name;
    }

    public String getDirectory() {
        return directory;
    }

    public String getDesc() {
        return desc;
    }

    public Map<String, EC_Data> getObjects() {
        return Collections.unmodifiableMap(objects);
    }

    public <T extends EC_Data> Map<String, T> getObjects(Class<T> cls) {
        Map<String, T> objs = new TreeMap<>();
        for (Map.Entry<String, EC_Data> entry : objects.entrySet()) {
            if (cls.isInstance(entry.getValue())) {
                objs.put(entry.getKey(), cls.cast(entry.getValue()));
            }
        }
        return Collections.unmodifiableMap(objs);
    }

    public <T extends EC_Data> T getObject(Class<T> cls, String id) {
        EC_Data obj = objects.get(id);
        if (cls.isInstance(obj)) {
            return cls.cast(obj);
        } else {
            return null;
        }
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();
        out.append("\t- ").append(name).append((desc == null || desc.equals("")) ? "" : ": " + desc);
        out.append(System.lineSeparator());

        Map<String, EC_Curve> curves = getObjects(EC_Curve.class);
        int size = curves.size();
        if (size > 0) {
            out.append("\t\tCurves: ");
            for (Map.Entry<String, EC_Curve> curve : curves.entrySet()) {
                out.append(curve.getKey());
                size--;
                if (size > 0)
                    out.append(", ");
            }
            out.append(System.lineSeparator());
        }

        Map<String, EC_Key> keys = getObjects(EC_Key.class);
        size = keys.size();
        if (size > 0) {
            out.append("\t\tKeys: ");
            for (Map.Entry<String, EC_Key> key : keys.entrySet()) {
                out.append(key.getKey());
                size--;
                if (size > 0)
                    out.append(", ");
            }
            out.append(System.lineSeparator());
        }

        Map<String, EC_Keypair> keypairs = getObjects(EC_Keypair.class);
        size = keypairs.size();
        if (size > 0) {
            out.append("\t\tKeypairs: ");
            for (Map.Entry<String, EC_Keypair> key : keypairs.entrySet()) {
                out.append(key.getKey());
                size--;
                if (size > 0)
                    out.append(", ");
            }
            out.append(System.lineSeparator());
        }

        Map<String, EC_KAResult> results = getObjects(EC_KAResult.class);
        size = results.size();
        if (size > 0) {
            out.append("\t\tResults: ");
            for (Map.Entry<String, EC_KAResult> result : results.entrySet()) {
                out.append(result.getKey());
                size--;
                if (size > 0)
                    out.append(", ");
            }
            out.append(System.lineSeparator());
        }
        return out.toString();
    }
}
