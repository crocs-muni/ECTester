package cz.crcs.ectester.common.cli;

import org.apache.commons.cli.*;

import java.util.*;

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

            List<String> matches = new LinkedList<>();
            String finalSub = sub;
            for (Map.Entry<String, ParserOptions> entry : parsers.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(finalSub)) {
                    matches.clear();
                    matches.add(finalSub);
                    break;
                } else if (entry.getKey().startsWith(finalSub)) {
                    matches.add(entry.getKey());
                }
            }

            if (matches.size() == 1) {
                sub = matches.get(0);
                ParserOptions subparser = parsers.get(sub);
                String[] remainingArgs = new String[args.length - 1];
                System.arraycopy(args, 1, remainingArgs, 0, args.length - 1);
                subCli = subparser.getParser().parse(subparser.getOptions(), remainingArgs, true);
            } else if (matches.size() > 1) {
                throw new UnrecognizedOptionException("Ambiguous option: " + sub + ", couldn't match. Partially matches: " + String.join(",", matches.toArray(new String[0])) + ".", sub);
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
