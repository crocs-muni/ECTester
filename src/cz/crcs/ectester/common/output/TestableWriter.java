package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.BaseTestable;
import cz.crcs.ectester.reader.output.ResponseWriter;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.CommandTestable;
import cz.crcs.ectester.standalone.test.KeyAgreementTestable;
import cz.crcs.ectester.standalone.test.KeyGeneratorTestable;
import cz.crcs.ectester.standalone.test.SignatureTestable;

import java.io.OutputStream;
import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TestableWriter {
    private PrintStream output;
    private ResponseWriter respWriter;

    public TestableWriter(PrintStream output) {
        this.output = output;
        this.respWriter = new ResponseWriter(output);
    }

    public TestableWriter(OutputStream output) {
        this(new PrintStream(output));
    }

    public String outputTestableSuffix(BaseTestable t) {
        if (t instanceof CommandTestable) {
            Response r = ((CommandTestable) t).getResponse();
            return respWriter.responseSuffix(r);
        } else if (t instanceof KeyAgreementTestable) {

        } else if (t instanceof KeyGeneratorTestable) {

        } else if (t instanceof SignatureTestable) {

        }
        return null;
    }

    public void writeTestableSuffix(BaseTestable t) {
        output.println(outputTestableSuffix(t));
    }

    public String outputTestable(BaseTestable t) {
        if (t instanceof CommandTestable) {
            CommandTestable testable = (CommandTestable) t;
            return respWriter.responseString(testable.getResponse());
        } else if (t instanceof KeyAgreementTestable) {

        } else if (t instanceof KeyGeneratorTestable) {

        } else if (t instanceof SignatureTestable) {

        }
        return null;
    }

    public void writeTestable(BaseTestable t) {
        output.println(outputTestable(t));
    }
}
