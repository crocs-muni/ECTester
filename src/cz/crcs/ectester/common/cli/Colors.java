package cz.crcs.ectester.common.cli;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Diogo Nunes
 * @author Jan Jancar johny@neuromancer.sk
 * Adapted from https://github.com/dialex/JCDP/
 */
public class Colors {
    public static boolean enabled = false;

    public interface ANSIParam {
    }

    public enum Foreground implements ANSIParam {
        BLACK("30"), RED("31"), GREEN("32"), YELLOW("33"), BLUE("34"), MAGENTA("35"), CYAN("36"), WHITE("37"), NONE("");
        private final String code;

        Foreground(String code) {
            this.code = code;
        }

        @Override
        public String toString() {
            return code;
        }
    }

    public enum Background implements ANSIParam {
        BLACK("40"), RED("41"), GREEN("42"), YELLOW("43"), BLUE("44"), MAGENTA("45"), CYAN("46"), WHITE("47"), NONE("");
        private final String code;

        Background(String code) {
            this.code = code;
        }

        @Override
        public String toString() {
            return code;
        }
    }

    public enum Attribute implements ANSIParam {
        CLEAR("0"), BOLD("1"), LIGHT("1"), DARK("2"), UNDERLINE("4"), REVERSE("7"), HIDDEN("8"), NONE("");
        private final String code;

        Attribute(String code) {
            this.code = code;
        }

        @Override
        public String toString() {
            return code;
        }
    }

    private static final String PREFIX = "\033[";
    private static final String SEPARATOR = ";";
    private static final String POSTFIX = "m";

    public static String colored(String text, ANSIParam... params) {
        if (!enabled) {
            return text;
        }
        Optional<Foreground> fg = Arrays.stream(params).filter(Foreground.class::isInstance).map(Foreground.class::cast).findFirst();
        Optional<Background> bg = Arrays.stream(params).filter(Background.class::isInstance).map(Background.class::cast).findFirst();
        List<Attribute> attr = Arrays.stream(params).filter(Attribute.class::isInstance).distinct().map(Attribute.class::cast).collect(Collectors.toList());

        List<ANSIParam> apply = new LinkedList<>();
        apply.addAll(attr);
        fg.ifPresent(apply::add);
        bg.ifPresent(apply::add);
        List<String> codes = apply.stream().map(Object::toString).collect(Collectors.toList());
        return PREFIX + String.join(SEPARATOR, codes) + POSTFIX + text + PREFIX + Attribute.CLEAR + POSTFIX;
    }

    public static String error(String text) {
        return colored(text, Foreground.RED, Attribute.BOLD);
    }

    public static String ok(String text) {
        return colored(text, Foreground.GREEN, Attribute.BOLD);
    }

    public static String bold(String text) {
        return colored(text, Attribute.BOLD);
    }

    public static String underline(String text) {
        return colored(text, Attribute.UNDERLINE);
    }
}