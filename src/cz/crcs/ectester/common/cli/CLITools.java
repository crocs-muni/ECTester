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
        help.printHelp(Colors.bold(prog), header, options, footer, usage);
    }

    private static void help(HelpFormatter help, PrintWriter pw, String cmd, ParserOptions parser, int depth) {
        String description = parser.getDescription() == null ? "" : "    | " + parser.getDescription() + " |";
        help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, String.format("%" + depth + "s" + cmd + ":" + description, " "));
        CLITools.help(help, pw, parser.getParser(), parser.getOptions(), depth + 1);
    }

    private static void help(HelpFormatter help, PrintWriter pw, CommandLineParser cli, Options opts, int depth) {
        if (opts.getOptions().size() > 0) {
            help.printOptions(pw, HelpFormatter.DEFAULT_WIDTH, opts, HelpFormatter.DEFAULT_LEFT_PAD + depth, HelpFormatter.DEFAULT_DESC_PAD);
        }
        if (cli instanceof TreeParser) {
            TreeParser tp = (TreeParser) cli;
            for (Argument arg : tp.getArgs()) {
                String argname = arg.isRequired() ? "<" + arg.getName() + ">" : "[" + arg.getName() + "]";
                help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, String.format("%" + (depth + 1) + "s" + argname + "   " + arg.getDesc(), " "));
            }
            tp.getParsers().forEach((key, value) -> {
                pw.println();
                help(help, pw, key, value, depth);
            });
        }
    }

    private static void usage(HelpFormatter help, PrintWriter pw, CommandLineParser cli, Options opts) {
        StringWriter sw = new StringWriter();
        PrintWriter upw = new PrintWriter(sw);
        help.printUsage(upw, HelpFormatter.DEFAULT_WIDTH, "", opts);
        if (cli instanceof TreeParser) {
            upw.print(" ");
            TreeParser tp = (TreeParser) cli;
            String[] keys = tp.getParsers().keySet().toArray(new String[tp.getParsers().size()]);
            if (keys.length > 0 && !tp.isRequired()) {
                upw.print("[ ");
            }

            for (int i = 0; i < keys.length; ++i) {
                String key = keys[i];
                ParserOptions value = tp.getParsers().get(key);
                upw.print("(" + key);
                usage(help, upw, value.getParser(), value.getOptions());
                upw.print(")");
                if (i != keys.length - 1) {
                    upw.print(" | ");
                }
            }

            if (keys.length > 0 && !tp.isRequired()) {
                upw.print(" ]");
            }

            Argument[] args = tp.getArgs().toArray(new Argument[tp.getArgs().size()]);
            if (args.length > 0) {
                String[] argss = new String[tp.getArgs().size()];
                for (int i = 0; i < args.length; ++i) {
                    Argument arg = args[i];
                    argss[i] = arg.isRequired() ? "<" + arg.getName() + ">" : "[" + arg.getName() + "]";
                }
                upw.print(" " + String.join(" ", argss));
            }
        }
        pw.println(sw.toString().replaceAll("usage:( )?", "").replace("\n", ""));
    }

    /**
     * Print tree help.
     */
    public static void help(String prog, String header, Options baseOpts, TreeParser baseParser, String footer, boolean printUsage) {
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, header);
        if (printUsage) {
            StringWriter uw = new StringWriter();
            PrintWriter upw = new PrintWriter(uw);
            usage(help, upw, baseParser, baseOpts);
            pw.print("usage: " + Colors.bold(prog));
            help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, uw.toString());
            upw.close();
            pw.println();
        }
        help(help, pw, baseParser, baseOpts, 1);
        help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, footer);
        System.out.println(sw.toString());
    }

    public static void help(String header, TreeParser baseParser, String footer, String command) {
        ParserOptions opts = baseParser.getParsers().get(command);
        if (opts == null) {
            System.err.println("Command not found: " + command);
            return;
        }
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        help.printWrapped(pw, HelpFormatter.DEFAULT_WIDTH, header);
        help(help, pw, command, opts, 1);
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
