package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.common.cli.Colors;

import java.util.*;
import java.util.stream.Collectors;

/**
 * A category of EC_Data objects, has a name, description and represents a directory in
 * the cz.crcs.ectester.data package.
 *
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

        String[] headers = new String[]{"Curves", "Public keys", "Private keys", "KeyPairs", "Results(KA)", "Results(SIG)"};
        Class<EC_Data>[] classes = new Class[]{EC_Curve.class, EC_Key.Public.class, EC_Key.Private.class, EC_Keypair.class, EC_KAResult.class, EC_SigResult.class};
        for (int i = 0; i < headers.length; ++i) {
            Map<String, EC_Data> data = getObjects(classes[i]);
            int size = data.size();
            if (size > 0) {
                out.append(Colors.bold(String.format("\t\t%s: ", headers[i])));
                List<EC_Data> sorted = new ArrayList<>(data.values());
                Collections.sort(sorted);
                for (EC_Data element : sorted) {
                    out.append(element.getId());
                    size--;
                    if (size > 0)
                        out.append(", ");
                }
                out.append(System.lineSeparator());
            }
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
