package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.test.BaseTestable;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

import javax.smartcardio.CardException;
import java.util.function.Supplier;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CommandTestable extends BaseTestable {
    protected Command command;
    protected Response response;

    public CommandTestable(Command command) {
        this.command = command;
    }

    public Command getCommand() {
        return command;
    }

    public Response getResponse() {
        return response;
    }

    @Override
    public void run() {
        try {
            response = command.send();
        } catch (CardException e) {
            throw new TestException(e);
        }

        hasRun = true;
        if (response.error()) {
            error = true;
        } else if (response.successful()) {
            ok = true;
        }
    }

    public static class FunctionCommandTestable extends CommandTestable {
        private Supplier<Command> supplier;

        public FunctionCommandTestable(Supplier<Command> supplier) {
            super(null);
            this.supplier = supplier;
        }

        @Override
        public void run() {
            this.command = supplier.get();
            super.run();
        }
    }
}
