package cz.crcs.ectester.common.cli;

import org.apache.commons.cli.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TreeParser implements CommandLineParser {
    private Map<String, ParserOptions> parsers;
    private boolean required;
    private List<Argument> args = Collections.emptyList();

    public TreeParser(Map<String, ParserOptions> parsers, boolean required) {
        this.parsers = parsers;
        this.required = required;
    }

    public TreeParser(Map<String, ParserOptions> parsers, boolean required, List<Argument> args) {
        this(parsers, required);
        this.args = args;
    }

    public Map<String, ParserOptions> getParsers() {
        return Collections.unmodifiableMap(parsers);
    }

    public boolean isRequired() {
        return required;
    }

    public List<Argument> getArgs() {
        return Collections.unmodifiableList(args);
    }

    @Override
    public TreeCommandLine parse(Options options, String[] arguments) throws ParseException {
        return this.parse(options, arguments, null);
    }

    public TreeCommandLine parse(Options options, String[] arguments, Properties properties) throws ParseException {
        return this.parse(options, arguments, properties, false);
    }

    @Override
    public TreeCommandLine parse(Options options, String[] arguments, boolean stopAtNonOption) throws ParseException {
        return this.parse(options, arguments, null, stopAtNonOption);
    }

    public TreeCommandLine parse(Options options, String[] arguments, Properties properties, boolean stopAtNonOption) throws ParseException {
        DefaultParser thisParser = new DefaultParser();
        CommandLine cli = thisParser.parse(options, arguments, properties, true);
        //System.err.println("arguments " + Arrays.toString(arguments));
        //System.err.println("args " + Arrays.toString(args.stream().map(Argument::getName).collect(Collectors.toList()).toArray()));

        CommandLine subCli = null;
        String[] cliArgs = cli.getArgs();
        //System.err.println(Arrays.toString(cliArgs));
        String sub = null;
        if (cliArgs.length != 0) {
            sub = cliArgs[0];

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
                //System.err.println("found sub ->" + sub);
                String[] remainingArgs = new String[cliArgs.length - 1];
                System.arraycopy(cliArgs, 1, remainingArgs, 0, cliArgs.length - 1);
                subCli = subparser.getParser().parse(subparser.getOptions(), remainingArgs, true);
            } else if (matches.size() > 1) {
                throw new AmbiguousOptionException(sub, matches);
            }
        } else {
            if (required) {
                throw new MissingOptionException(new ArrayList<>(parsers.keySet()));
            }
        }

        int maxArgs = args.size();
        long requiredArgs = args.stream().filter(Argument::isRequired).count();
        String reqArgs = String.join(" ", args.stream().filter(Argument::isRequired).map(Argument::getName).collect(Collectors.toList()));

        if (subCli instanceof TreeCommandLine) {
            TreeCommandLine subTreeCli = (TreeCommandLine) subCli;
            subTreeCli.setName(sub);
            return new TreeCommandLine(cli, subTreeCli);
        } else if (subCli != null) {
            //System.err.println("subCli " + subCli.getArgs().length + " maxArgs " + maxArgs);
            if (subCli.getArgs().length < requiredArgs) {
                throw new MissingArgumentException("Not enough arguments: " + reqArgs);
            } else if (subCli.getArgs().length > maxArgs) {
                for (String arg : subCli.getArgs()) {
                    if (arg.startsWith("-")) {
                        throw new UnrecognizedOptionException("Option " + arg + " not recognized.");
                    }
                }
                throw new MissingArgumentException("Too many arguments: " + Arrays.toString(cliArgs));
            }

            TreeCommandLine subTreeCli = new TreeCommandLine(sub, subCli, null);
            return new TreeCommandLine(cli, subTreeCli);
        } else {
            //System.err.println("cliArgs " + cliArgs.length + " maxArgs " + maxArgs);
            if (cliArgs.length < requiredArgs) {
                throw new MissingArgumentException("Not enough arguments: " + reqArgs);
            } else if (cliArgs.length > maxArgs) {
                for (String arg : cliArgs) {
                    if (arg.startsWith("-")) {
                        throw new UnrecognizedOptionException("Option " + arg + " not recognized.");
                    }
                }
                throw new MissingArgumentException("Too many arguments: " + Arrays.toString(cliArgs));
            }

            return new TreeCommandLine(cli, null);
        }
    }
}
