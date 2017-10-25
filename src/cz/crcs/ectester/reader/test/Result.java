package cz.crcs.ectester.reader.test;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class Result {

    private Value value;
    private String cause;

    public Result(Value value) {
        this.value = value;
    }

    public Result(Value value, String cause) {
        this(value);
        this.cause = cause;
    }

    public Value getValue() {
        return value;
    }

    public String getCause() {
        return cause;
    }

    public enum Value {
        SUCCESS,
        FAILURE,
        ANY
    }

    public boolean compareTo(Result other) {
        if (other == null) {
            return false;
        }
        return value == other.value;
    }

    public boolean compareTo(Value other) {
        if (other == null) {
            return false;
        }
        return value == other;
    }
}
