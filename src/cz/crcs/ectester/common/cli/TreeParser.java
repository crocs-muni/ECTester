package cz.crcs.ectester.common.cli;

import org.apache.commons.cli.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TreeParser implements CommandLineParser {
    private Map<String, ParserOptions> parsers;
    private boolean required;

    public TreeParser(Map<String, ParserOptions> parsers, boolean required) {
        this.parsers = parsers;
        this.required = required;
    }

    public Map<String, ParserOptions> getParsers() {
        return Collections.unmodifiableMap(parsers);
    }

    public boolean isRequired() {
        return required;
    }

    @Override
    public CommandLine parse(Options options, String[] arguments) throws ParseException {
        return this.parse(options, arguments, null);
    }

    public CommandLine parse(Options options, String[] arguments, Properties properties) throws ParseException {
        return this.parse(options, arguments, properties, false);
    }

    @Override
    public CommandLine parse(Options options, String[] arguments, boolean stopAtNonOption) throws ParseException {
        return this.parse(options, arguments, null, stopAtNonOption);
    }

    public CommandLine parse(Options options, String[] arguments, Properties properties, boolean stopAtNonOption) throws ParseException {
        DefaultParser thisParser = new DefaultParser();
        CommandLine cli = thisParser.parse(options, arguments, properties, true);

        CommandLine subCli = null;
        String[] args = cli.getArgs();
        String sub = null;
        if (args.length != 0) {
            sub = args[0];
            ParserOptions subparser = parsers.get(sub);
            if (subparser != null) {
                String[] remainingArgs = new String[args.length - 1];
                System.arraycopy(args, 1, remainingArgs, 0, args.length - 1);
                subCli = subparser.getParser().parse(subparser.getOptions(), remainingArgs, true);
            }
        } else {
            if (required) {
                throw new MissingOptionException(new ArrayList(parsers.keySet()));
            }
        }
        if (subCli instanceof TreeCommandLine) {
            TreeCommandLine subTreeCli = (TreeCommandLine) subCli;
            subTreeCli.setName(sub);
            return new TreeCommandLine(cli, subTreeCli);
        } else if (subCli != null) {
            TreeCommandLine subTreeCli = new TreeCommandLine(sub, subCli, null);
            return new TreeCommandLine(cli, subTreeCli);
        } else {
            return new TreeCommandLine(cli, null);
        }
    }
}
