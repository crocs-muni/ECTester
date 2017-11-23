package cz.crcs.ectester.common.cli;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;

import java.util.Collections;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ParserOptions {
    private CommandLineParser parser;
    private Options options;
    private List<Argument> arguments;

    public ParserOptions(CommandLineParser parser, Options options) {
        this.parser = parser;
        this.options = options;
    }

    public ParserOptions(CommandLineParser parser, Options options, List<Argument> arguments) {
        this(parser, options);
        this.arguments = arguments;
    }

    public CommandLineParser getParser() {
        return parser;
    }

    public Options getOptions() {
        return options;
    }

    public List<Argument> getArguments() {
        return Collections.unmodifiableList(arguments);
    }
}
