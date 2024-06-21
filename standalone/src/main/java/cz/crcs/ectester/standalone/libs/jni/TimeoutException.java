package cz.crcs.ectester.standalone.libs.jni;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TimeoutException extends RuntimeException {

    public TimeoutException(String message) {
        super(message);
    }
}
