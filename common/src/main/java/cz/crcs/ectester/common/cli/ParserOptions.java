package cz.crcs.ectester.common.cli;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ParserOptions {
    private CommandLineParser parser;
    private Options options;
    private String description;

    public ParserOptions(CommandLineParser parser, Options options) {
        this.parser = parser;
        this.options = options;
    }

    public ParserOptions(CommandLineParser parser, Options options, String description) {
        this(parser, options);
        this.description = description;
    }

    public CommandLineParser getParser() {
        return parser;
    }

    public Options getOptions() {
        return options;
    }

    public String getDescription() {
        return description;
    }
}
