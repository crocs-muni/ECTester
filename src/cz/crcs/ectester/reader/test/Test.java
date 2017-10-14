package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

import javax.smartcardio.CardException;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * An abstract test that can be run and has a Result.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Test {
    boolean hasRun = false;
    Result result;

    public Result getResult() {
        if (!hasRun) {
            return null;
        }
        return result;
    }

    public boolean hasRun() {
        return hasRun;
    }

    public abstract boolean ok();

    public abstract void run() throws CardException;

    /**
     * A result of a Test.
     */
    public enum Result {
        SUCCESS,
        FAILURE,
        ANY
    }

    /**
     * A simple test that runs one Command to get and evaluate one Response
     * to get a Result and compare it with the expected one.
     */
    public static class Simple extends Test {
        private BiFunction<Command, Response, Result> callback;
        private Result expected;
        private Command command;
        private Response response;

        public Simple(Command command, Result expected) {
            this.command = command;
            this.expected = expected;
        }

        public Simple(Command command, Result expected, BiFunction<Command, Response, Result> callback) {
            this(command, expected);
            this.callback = callback;
        }

        public Command getCommand() {
            return command;
        }

        public Response getResponse() {
            return response;
        }

        public Result getExpected() {
            return expected;
        }

        @Override
        public boolean ok() {
            return result == expected || expected == Result.ANY;
        }

        @Override
        public void run() throws CardException {
            response = command.send();
            if (callback != null) {
                result = callback.apply(command, response);
            } else {
                if (response.successful()) {
                    result = Result.SUCCESS;
                } else {
                    result = Result.FAILURE;
                }
            }
            hasRun = true;
        }

        @Override
        public String toString() {
            if (hasRun) {
                return (ok() ? "OK " : "NOK") + " " + response.toString();
            } else {
                return "";
            }
        }
    }

    /**
     * A compound test that runs many Tests and has a Result dependent on all/some of their Results.
     */
    public static class Compound extends Test {
        private Function<Test[], Result> callback;
        private Test[] tests;

        private Compound(Function<Test[], Result> callback, Test... tests) {
            this.callback = callback;
            this.tests = tests;
        }

        public Compound function(Function<Test[], Result> callback, Test... tests) {
            return new Compound(callback, tests);
        }

        public Compound all(Result what, Test... all) {
            return new Compound((tests) -> {
                for (Test test : tests) {
                    if (test.getResult() != what) {
                        return Result.FAILURE;
                    }
                }
                return Result.SUCCESS;
            }, all);
        }

        public Compound any(Result what, Test... any) {
            return new Compound((tests) -> {
                for (Test test : tests) {
                    if (test.getResult() == what) {
                        return Result.SUCCESS;
                    }
                }
                return Result.FAILURE;
            }, any);
        }

        @Override
        public boolean ok() {
            return result == Result.SUCCESS;
        }

        @Override
        public void run() throws CardException {
            for (Test test: tests) {
                test.run();
            }
            result = callback.apply(tests);
        }
    }
}
