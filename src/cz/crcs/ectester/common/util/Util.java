package cz.crcs.ectester.common.util;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class Util {
    public static long convertTime(long nanos, String timeUnit) {
        switch (timeUnit) {
            default:
            case "nano":
                return nanos;
            case "micro":
                return nanos / 1000;
            case "milli":
                return nanos / 1000000;
        }
    }
}
