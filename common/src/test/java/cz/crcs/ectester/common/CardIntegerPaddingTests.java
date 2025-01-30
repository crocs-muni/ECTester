package cz.crcs.ectester.common;

import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.data.EC_Store;
import org.junit.jupiter.api.Test;
import org.opentest4j.AssertionFailedError;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CardIntegerPaddingTests {

    @Test
    public void testKeys() {
        EC_Store store = EC_Store.getInstance();
        Map<String, EC_Category> categories = store.getCategories();
        List<AssertionFailedError> errors = new ArrayList<>();

        for (EC_Category category : categories.values()) {
            Map<String, EC_Data> objects = category.getObjects();
            List<EC_Key> keys = new ArrayList<>();
            for (EC_Data object : objects.values()) {
                if (object instanceof EC_Key) {
                    EC_Key key = (EC_Key) object;
                    keys.add(key);
                }
            }
            Map<EC_Curve, List<EC_Key>> keyMap = EC_Store.mapKeyToCurve(keys);
            for (EC_Curve curve : keyMap.keySet()) {
                List<EC_Key> curveKeys = keyMap.get(curve);
                int bits = curve.getBits();
                int bytes = (bits + 7) / 8;
                for (EC_Key key : curveKeys) {
                    if (key instanceof EC_Key.Private) {
                        continue;
                    }
                    byte[][] data = key.getData();
                    byte[] xCoord = data[0];
                    byte[] yCoord = data[1];
                    try {
                        assertEquals(bytes, xCoord.length, "Curve: " + curve.getId() + ", Key: " + category.getName() + "/" + key.getId() + " (x)");
                    } catch (AssertionFailedError e) {
                        errors.add(e);
                    }
                    try {
                        assertEquals(bytes, yCoord.length, "Curve: " + curve.getId() + ", Key: " + category.getName() + "/" + key.getId() + " (y)");
                    } catch (AssertionFailedError e) {
                        errors.add(e);
                    }
                }
            }
        }

        if (!errors.isEmpty()) {
            StringBuilder sb = new StringBuilder("There were assertion errors:\n");
            for (AssertionFailedError error : errors) {
                sb.append(error.getMessage()).append("\n");
            }
            AssertionFailedError e = new AssertionFailedError(sb.toString());
            for (AssertionFailedError error : errors) {
                e.addSuppressed(error);
            }
            throw e;
        }
    }

    @Test
    public void testCurves() {
        EC_Store store = EC_Store.getInstance();
        Map<String, EC_Category> categories = store.getCategories();
        List<AssertionFailedError> errors = new ArrayList<>();

        for (EC_Category category : categories.values()) {
            Map<String, EC_Data> objects = category.getObjects();
            for (EC_Data object : objects.values()) {
                if (object instanceof EC_Curve) {
                    EC_Curve curve = (EC_Curve) object;
                    if (curve.getField() == EC_Consts.ALG_EC_FP) {
                        int bits = curve.getBits();
                        int bytes = (bits + 7) / 8;
                        byte[][] generator = curve.getParam(EC_Consts.PARAMETER_G);
                        byte[] xCoord = generator[0];
                        byte[] yCoord = generator[1];
                        try {
                            assertEquals(bytes, xCoord.length, "Curve: " + category.getName() + "/" + curve.getId() + " (generator x)");
                        } catch (AssertionFailedError e) {
                            errors.add(e);
                        }
                        try {
                            assertEquals(bytes, yCoord.length, "Curve: " + category.getName() + "/" + curve.getId() + " (generator y)");
                        } catch (AssertionFailedError e) {
                            errors.add(e);
                        }
                    }
                }
            }
        }

        if (!errors.isEmpty()) {
            StringBuilder sb = new StringBuilder("There were assertion errors:\n");
            for (AssertionFailedError error : errors) {
                sb.append(error.getMessage()).append("\n");
            }
            AssertionFailedError e = new AssertionFailedError(sb.toString());
            for (AssertionFailedError error : errors) {
                e.addSuppressed(error);
            }
            throw e;
        }
    }
}
