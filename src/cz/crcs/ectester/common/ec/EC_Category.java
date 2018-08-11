package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.common.cli.Colors;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * A category of EC_Data objects, has a name, description and represents a directory in
 * the cz.crcs.ectester.data package.
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
        out.append("\t- ").append(Colors.bold(name)).append((desc == null || desc.equals("")) ? "" : ": " + desc);
        out.append(System.lineSeparator());

        Map<String, EC_Curve> curves = getObjects(EC_Curve.class);
        int size = curves.size();
        if (size > 0) {
            out.append(Colors.bold("\t\tCurves: "));
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
            out.append(Colors.bold("\t\tKeys: "));
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
            out.append(Colors.bold("\t\tKeypairs: "));
            for (Map.Entry<String, EC_Keypair> key : keypairs.entrySet()) {
                out.append(key.getKey());
                size--;
                if (size > 0)
                    out.append(", ");
            }
            out.append(System.lineSeparator());
        }

        Map<String, EC_KAResult> kaResults = getObjects(EC_KAResult.class);
        size = kaResults.size();
        if (size > 0) {
            out.append(Colors.bold("\t\tResults(KA): "));
            for (Map.Entry<String, EC_KAResult> result : kaResults.entrySet()) {
                out.append(result.getKey());
                size--;
                if (size > 0)
                    out.append(", ");
            }
            out.append(System.lineSeparator());
        }

        Map<String, EC_SigResult> sigResults = getObjects(EC_SigResult.class);
        size = sigResults.size();
        if (size > 0) {
            out.append(Colors.bold("\t\tResults(SIG): "));
            for (Map.Entry<String, EC_SigResult> result : sigResults.entrySet()) {
                out.append(result.getKey());
                size--;
                if (size > 0)
                    out.append(", ");
            }
            out.append(System.lineSeparator());
        }
        return out.toString();
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof EC_Category && Objects.equals(this.name, ((EC_Category) obj).name);
    }

    @Override
    public int hashCode() {
        return this.name.hashCode() ^ this.directory.hashCode();
    }

}
