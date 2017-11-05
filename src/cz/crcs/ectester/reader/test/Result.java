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

    public boolean ok() {
        return value.ok();
    }

    public enum Value {
        SUCCESS(true),
        FAILURE(false),
        UXSUCCESS(false),
        XFAILURE(true);

        private boolean ok;

        Value(boolean ok) {
            this.ok = ok;
        }

        public static Value fromExpected(ExpectedValue expected, boolean successful) {
            switch (expected) {
                case SUCCESS:
                    return successful ? SUCCESS : FAILURE;
                case FAILURE:
                    return successful ? UXSUCCESS : XFAILURE;
                case ANY:
                    return SUCCESS;
            }
            return SUCCESS;
        }

        public boolean ok() {
            return ok;
        }
    }

    public enum ExpectedValue {
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
