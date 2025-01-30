package cz.crcs.ectester.common;

import cz.crcs.ectester.common.ec.EC_Category;
import cz.crcs.ectester.common.ec.EC_Data;
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.data.EC_Store;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ParamSerializationTests {

    @Test
    public void test() {
        EC_Store store = EC_Store.getInstance();
        Map<String, EC_Category> categories = store.getCategories();

        for (EC_Category category : categories.values()) {
            Map<String, EC_Data> objects = category.getObjects();
            for (EC_Data object : objects.values()) {
                if (object instanceof EC_Params) {
                    EC_Params params = (EC_Params) object;
                    byte[] serialized = params.flatten();
                    EC_Params deserialized = new EC_Params(params.getId(), params.getParams());
                    deserialized.inflate(serialized);
                    assertEquals(params, deserialized, "Category: " + category.getName() + ", Params: " + params.getId());
                }
            }
        }
    }
}
