package cz.crcs.ectester.common.test;

/**
 * A Result of a Test. Has a Value and an optional String cause.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class Result {

    private Value value;
    private Object cause;

    public Result(Value value) {
        this.value = value;
    }

    public Result(Value value, Object cause) {
        this(value);
        this.cause = cause;
    }

    public Value getValue() {
        return value;
    }

    public Object getCause() {
        return cause;
    }

    public boolean ok() {
        return value.ok();
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

    /**
     * A result value of a Test.
     */
    public enum Value {
        SUCCESS(true, true, "Expected success."),
        FAILURE(false, false, "Unexpected failure."),
        UXSUCCESS(false, true, "Unexpected success."),
        XFAILURE(true, false, "Expected failure."),
        OKSUCCESS(true, true, "Any result is OK."),
        OKFAILURE(true, false, "Any result is OK."),
        ERROR(false, false, "Error.");

        private boolean ok;
        private boolean successful;
        private String desc;

        Value(boolean ok, boolean successful) {
            this.ok = ok;
            this.successful = successful;
        }

        Value(boolean ok, boolean successful, String desc) {
            this(ok, successful);
            this.desc = desc;
        }

        public static Value fromExpected(ExpectedValue expected, boolean successful) {
            switch (expected) {
                case SUCCESS:
                    return successful ? SUCCESS : FAILURE;
                case FAILURE:
                    return successful ? UXSUCCESS : XFAILURE;
                case ANY:
                    return successful ? OKSUCCESS : OKFAILURE;
            }
            return SUCCESS;
        }

        public static Value fromExpected(ExpectedValue expected, boolean successful, boolean error) {
            if (error) {
                return ERROR;
            }
            return fromExpected(expected, successful);
        }

        public boolean ok() {
            return ok;
        }

        public boolean successful() {
            return successful;
        }

        public String description() {
            return desc;
        }
    }

    /**
     * A possible expected value result of a Test.
     */
    public enum ExpectedValue {
        SUCCESS,
        FAILURE,
        ANY
    }
}
