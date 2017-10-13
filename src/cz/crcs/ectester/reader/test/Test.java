package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

import javax.smartcardio.CardException;
import java.util.function.BiFunction;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class Test {
    private boolean hasRun = false;
    private BiFunction<Command, Response, Result> callback;
    private Result result;
    private Result expected;
    private Command command;
    private Response response;

    public Test(Command command, Result expected) {
        this.command = command;
        this.expected = expected;
    }

    public Test(Command command, Result expected, BiFunction<Command, Response, Result> callback) {
        this(command, expected);
        this.callback = callback;
    }

    public Command getCommand() {
        return command;
    }

    public Response getResponse() {
        return response;
    }

    public Result getResult() {
        if (!hasRun) {
            return null;
        }
        return result;
    }

    public Result getExpected() {
        return expected;
    }

    public boolean ok() {
        return result == expected || expected == Result.ANY;
    }

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

    public boolean hasRun() {
        return hasRun;
    }

    @Override
    public String toString() {
        if (hasRun) {
            return (ok() ? "OK " : "NOK") + " " + response.toString();
        } else {
            return "";
        }
    }

    public enum Result {
        SUCCESS,
        FAILURE,
        ANY
    }
}
