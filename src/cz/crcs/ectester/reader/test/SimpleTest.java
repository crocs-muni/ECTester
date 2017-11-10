package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

import javax.smartcardio.CardException;
import java.util.function.BiFunction;

/**
 * A simple test that runs one Command to get and evaluate one Response
 * to get a Result and compare it with the expected one.
 */
public class SimpleTest extends Test {
    private BiFunction<Command, Response, Result> callback;
    private Command command;
    private Response response;

    public SimpleTest(Command command, BiFunction<Command, Response, Result> callback) {
        this.command = command;
        this.callback = callback;
    }

    public SimpleTest(Command command, Result.ExpectedValue expected, String ok, String nok) {
        this(command, (cmd, resp) -> {
            Result.Value resultValue = Result.Value.fromExpected(expected, resp.successful(), resp.error());
            return new Result(resultValue, resultValue.ok() ? ok : nok);
        });
    }

    public SimpleTest(Command command, Result.ExpectedValue expected) {
        this(command, expected, null, null);
    }

    public Command getCommand() {
        return command;
    }

    public Response getResponse() {
        return response;
    }

    @Override
    public void run() throws TestException {
        if (hasRun)
            return;

        try {
            response = command.send();
        } catch (CardException e) {
            throw new TestException(e);
        }
        if (callback != null) {
            result = callback.apply(command, response);
        } else {
            if (response.successful()) {
                result = new Result(Result.Value.SUCCESS);
            } else {
                result = new Result(Result.Value.FAILURE);
            }
        }
        hasRun = true;
    }

    @Override
    public String getDescription() {
        return response.getDescription();
    }
}
