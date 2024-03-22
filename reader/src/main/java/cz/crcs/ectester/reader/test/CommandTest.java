package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

import java.util.Arrays;

/**
 * A simple test that runs one Command to get and evaluate one Response
 * to get a Result and compare it with the expected one.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CommandTest extends SimpleTest<CommandTestable> {
    private CommandTest(CommandTestable command, TestCallback<CommandTestable> callback) {
        super(command, callback);
    }

    public static CommandTest function(CommandTestable command, TestCallback<CommandTestable> callback) {
        return new CommandTest(command, callback);
    }

    public static CommandTest function(Command command, TestCallback<CommandTestable> callback) {
        return function(new CommandTestable(command), callback);
    }

    public static CommandTest expect(CommandTestable command, Result.ExpectedValue expected, String ok, String nok) {
        return new CommandTest(command, new TestCallback<CommandTestable>() {
            @Override
            public Result apply(CommandTestable commandTestable) {
                Result.Value resultValue = Result.Value.fromExpected(expected, commandTestable.ok(), commandTestable.error());
                return new Result(resultValue, commandTestable.error() ? commandTestable.errorCause() : (resultValue.ok() ? ok : nok));
            }
        });
    }

    public static CommandTest expect(Command command, Result.ExpectedValue expectedValue, String ok, String nok) {
        return expect(new CommandTestable(command), expectedValue, ok, nok);
    }

    public static CommandTest expect(CommandTestable command, Result.ExpectedValue expected) {
        return expect(command, expected, null, null);
    }

    public static CommandTest expect(Command command, Result.ExpectedValue expectedValue) {
        return expect(command, expectedValue, null, null);
    }

    public static CommandTest expectSW(CommandTestable command, short... expectedSWS) {
        return new CommandTest(command, new TestCallback<CommandTestable>() {
            @Override
            public Result apply(CommandTestable commandTestable) {
                if (Arrays.equals(commandTestable.getResponse().getSWs(), expectedSWS)) {
                    return new Result(Result.Value.SUCCESS);
                } else {
                    return new Result(Result.Value.FAILURE);
                }
            }
        });
    }

    public static CommandTest expectSW(Command command, short... expectedSWS) {
        return expectSW(new CommandTestable(command), expectedSWS);
    }

    public Command getCommand() {
        return testable.getCommand();
    }

    public Response getResponse() {
        return testable.getResponse();
    }

    @Override
    public String getDescription() {
        if (hasRun) {
            return testable.getResponse().getDescription();
        } else {
            return testable.getCommand().getDescription();
        }
    }
}
