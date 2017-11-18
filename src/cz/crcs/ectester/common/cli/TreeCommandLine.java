package cz.crcs.ectester.common.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.function.BiFunction;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TreeCommandLine extends CommandLine {
    private String name = "";
    private TreeCommandLine next;
    private CommandLine cli;

    public TreeCommandLine(CommandLine cli, TreeCommandLine next) {
        this.cli = cli;
        this.next = next;
    }

    public TreeCommandLine(String name, CommandLine cli, TreeCommandLine next) {
        this(cli, next);
        this.name = name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public String getNextName() {
        if (next != null) {
            return next.getName();
        }
        return null;
    }

    public TreeCommandLine getNext() {
        return next;
    }

    public boolean isNext(String next) {
        return Objects.equals(getNextName(), next);
    }

    public CommandLine getThis() {
        return cli;
    }

    private <T> T getOption(String opt, BiFunction<CommandLine, String, T> getter, T defaultValue) {
        if (opt.contains(".")) {
            String[] parts = opt.split("\\.", 2);
            if (next != null && parts[0].equals(next.getName())) {
                return getter.apply(next, parts[1]);
            }
            return defaultValue;
        }
        return getter.apply(cli, opt);
    }

    @Override
    public boolean hasOption(String opt) {
        return getOption(opt, CommandLine::hasOption, false);
    }

    @Override
    public boolean hasOption(char opt) {
        return cli.hasOption(opt);
    }

    @Override
    public Object getParsedOptionValue(String opt) throws ParseException {
        if (opt.contains(".")) {
            String[] parts = opt.split(".", 2);
            if (next != null && parts[0].equals(next.getName())) {
                return next.getParsedOptionValue(parts[1]);
            }
            return null;
        }
        return cli.getParsedOptionValue(opt);
    }

    @Override
    public Object getOptionObject(char opt) {
        return cli.getOptionObject(opt);
    }

    @Override
    public String getOptionValue(String opt) {
        return getOption(opt, CommandLine::getOptionValue, null);
    }

    @Override
    public String getOptionValue(char opt) {
        return cli.getOptionValue(opt);
    }

    @Override
    public String[] getOptionValues(String opt) {
        return getOption(opt, CommandLine::getOptionValues, null);
    }

    @Override
    public String[] getOptionValues(char opt) {
        return cli.getOptionValues(opt);
    }

    @Override
    public String getOptionValue(String opt, String defaultValue) {
        return getOption(opt, CommandLine::getOptionValue, defaultValue);
    }

    @Override
    public String getOptionValue(char opt, String defaultValue) {
        return cli.getOptionValue(opt, defaultValue);
    }

    @Override
    public Properties getOptionProperties(String opt) {
        return getOption(opt, CommandLine::getOptionProperties, new Properties());
    }

    @Override
    public Iterator<Option> iterator() {
        return cli.iterator();
    }

    @Override
    public Option[] getOptions() {
        return cli.getOptions();
    }

    public String getArg(int index) {
        if (index < 0 || index >= cli.getArgs().length) {
            return null;
        }
        return cli.getArgs()[index];
    }

    @Override
    public String[] getArgs() {
        return cli.getArgs();
    }

    @Override
    public List<String> getArgList() {
        return cli.getArgList();
    }
}
