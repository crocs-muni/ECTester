package cz.crcs.ectester.data;

import cz.crcs.ectester.reader.ec.EC_Params;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Category {

    private String name;
    private String directory;
    private String desc;

    private Map<String, EC_Params> objects;


    public EC_Category(String name, String directory) {
        this.name = name;
        this.directory = directory;
    }

    public EC_Category(String name, String directory, String desc) {
        this(name, directory);
        this.desc = desc;
    }

    public EC_Category(String name, String directory, String desc, Map<String, EC_Params> objects) {
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

    public Map<String, EC_Params> getObjects() {
        return Collections.unmodifiableMap(objects);
    }

    public <T extends EC_Params> Map<String, T> getObjects(Class<T> cls) {
        Map<String, T> objs = new HashMap<>();
        for (Map.Entry<String, EC_Params> entry : objects.entrySet()) {
            if (cls.isInstance(entry.getValue())) {
                objs.put(entry.getKey(), cls.cast(entry.getValue()));
            }
        }
        return Collections.unmodifiableMap(objs);
    }

    public <T extends EC_Params> T getObject(Class<T> cls, String id) {
        EC_Params obj = objects.get(id);
        if (cls.isInstance(obj)) {
            return cls.cast(obj);
        } else {
            return null;
        }
    }
}
