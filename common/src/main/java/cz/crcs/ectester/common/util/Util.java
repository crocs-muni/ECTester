package cz.crcs.ectester.common.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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

    public static int getVersion() {
        String version = System.getProperty("java.version");
        if (version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            int dot = version.indexOf(".");
            if (dot != -1) {
                version = version.substring(0, dot);
            }
        }
        return Integer.parseInt(version);
    }

    public static SecureRandom getRandom(byte[] seed) {
        SecureRandom random;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ignored) {
            return null;
        }
        random.setSeed(seed);
        return random;
    }
}
