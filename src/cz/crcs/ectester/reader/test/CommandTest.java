package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

/**
 * A simple test that runs one Command to get and evaluate one Response
 * to get a Result and compare it with the expected one.
 */
public class CommandTest extends SimpleTest<CommandTestable> {
    private CommandTest(CommandTestable command, TestCallback<CommandTestable> callback) {
        super(command, callback);
    }

    public CommandTest expect(CommandTestable command, Result.ExpectedValue expected, String ok, String nok) {
        return new CommandTest(command, new TestCallback<CommandTestable>() {
            @Override
            public Result apply(CommandTestable commandTestable) {
                Response resp = commandTestable.getResponse();
                Result.Value resultValue = Result.Value.fromExpected(expected, resp.successful(), resp.error());
                return new Result(resultValue, resultValue.ok() ? ok : nok);
            }
        });
    }

    public CommandTest expect(CommandTestable command, Result.ExpectedValue expected) {
        return expect(command, expected, null, null);
    }

    public Command getCommand() {
        return testable.getCommand();
    }

    public Response getResponse() {
        return testable.getResponse();
    }

    @Override
    public void run() throws TestException {
        if (hasRun)
            return;

        testable.run();
        result = callback.apply(testable);
        hasRun = true;
    }

    @Override
    public String getDescription() {
        return null;
    }
}
