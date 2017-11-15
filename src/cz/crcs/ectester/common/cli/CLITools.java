package cz.crcs.ectester.common.cli;

import cz.crcs.ectester.common.ec.EC_Category;
import cz.crcs.ectester.common.ec.EC_Data;
import cz.crcs.ectester.data.EC_Store;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

import java.io.PrintWriter;
import java.io.StringWriter;
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

    private static void help(HelpFormatter help, PrintWriter pw, CommandLineParser cli, int depth) {
        if (cli instanceof TreeParser) {
            TreeParser tp = (TreeParser) cli;
            tp.getParsers().forEach((key, value) -> {
                help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, String.format("%" + String.valueOf(depth) + "s" + key + ":", " "));
                help.printOptions(pw, HelpFormatter.DEFAULT_WIDTH, value.getOptions(), HelpFormatter.DEFAULT_LEFT_PAD + depth, HelpFormatter.DEFAULT_DESC_PAD);
                pw.println();
                CLITools.help(help, pw, value.getParser(), depth + 1);
            });
        }
    }

    private static void usage(HelpFormatter help, PrintWriter pw, CommandLineParser cli, Options opts) {
        StringWriter sw = new StringWriter();
        PrintWriter upw = new PrintWriter(sw);
        help.printUsage(upw, HelpFormatter.DEFAULT_WIDTH, "", opts);
        upw.print(" ");
        if (cli instanceof TreeParser) {
            TreeParser tp = (TreeParser) cli;
            if (!tp.isRequired()) {
                upw.print("[ ");
            }
            tp.getParsers().forEach((key, value) -> {
                upw.print("( " + key + " ");
                usage(help, upw, value.getParser(), value.getOptions());
                upw.print(")");
            });
            if (!tp.isRequired()) {
                upw.print(" ]");
            }
        }
        pw.println(sw.toString().substring(8).replace("\n", ""));
    }

    /**
     * Print tree help.
     */
    public static void help(String prog, String header, Options baseOpts, TreeParser baseParser, String footer, boolean printUsage) {
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        if (printUsage) {
            StringWriter uw = new StringWriter();
            PrintWriter upw = new PrintWriter(uw);
            usage(help, upw, baseParser, baseOpts);
            pw.print(prog + " usage: ");
            help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, uw.toString());
            upw.close();
        }
        help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, header);
        help.printOptions(pw, HelpFormatter.DEFAULT_WIDTH, baseOpts, HelpFormatter.DEFAULT_LEFT_PAD, HelpFormatter.DEFAULT_DESC_PAD);
        pw.println();
        help(help, pw, baseParser, 1);
        help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, footer);
        System.out.println(sw.toString());
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
