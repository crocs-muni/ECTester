package cz.crcs.ectester.common;

import cz.crcs.ectester.common.ec.EC_Category;
import cz.crcs.ectester.common.ec.EC_Data;
import cz.crcs.ectester.data.EC_Store;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CLITools {

    /**
     * Print help.
     */
    public static void help(String prog, String header, Options options, String footer, boolean usage) {
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        help.printHelp(prog, header, options, footer, usage);
    }

    /**
     * Print version info.
     */
    public static void version(String description, String license) {
        System.out.println(description);
        System.out.println(license);
    }

    /**
     * List categories and named curves.
     */
    public static void listNamed(EC_Store dataStore, String named) {
        Map<String, EC_Category> categories = dataStore.getCategories();
        if (named == null) {
            // print all categories, briefly
            for (EC_Category cat : categories.values()) {
                System.out.println(cat);
            }
        } else if (categories.containsKey(named)) {
            // print given category
            System.out.println(categories.get(named));
        } else {
            // print given object
            EC_Data object = dataStore.getObject(EC_Data.class, named);
            if (object != null) {
                System.out.println(object);
            } else {
                System.err.println("Named object " + named + " not found!");
            }
        }
    }
}
