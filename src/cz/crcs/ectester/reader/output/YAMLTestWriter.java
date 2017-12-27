package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.output.BaseYAMLTestWriter;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.CommandTestable;

import java.io.PrintStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class YAMLTestWriter extends BaseYAMLTestWriter {
    public YAMLTestWriter(PrintStream output) {
        super(output);
    }

    private Map<String, Object> commandObject(Command c) {
        Map<String, Object> commandObj = new HashMap<>();
        commandObj.put("apdu", ByteUtil.bytesToHex(c.getAPDU().getBytes()));
        return commandObj;
    }

    private Map<String, Object> responseObject(Response r) {
        Map<String, Object> responseObj = new HashMap<>();
        responseObj.put("successful", r.successful());
        responseObj.put("apdu", ByteUtil.bytesToHex(r.getAPDU().getBytes()));
        responseObj.put("natural_sw", Short.toUnsignedInt(r.getNaturalSW()));
        List<Integer> sws = new LinkedList<>();
        for (int i = 0; i < r.getNumSW(); ++i) {
            sws.add(Short.toUnsignedInt(r.getSW(i)));
        }
        responseObj.put("sws", sws);
        responseObj.put("duration", r.getDuration());
        responseObj.put("desc", r.getDescription());
        return responseObj;
    }

    @Override
    protected Map<String, Object> testableObject(Testable t) {
        if (t instanceof CommandTestable) {
            CommandTestable cmd = (CommandTestable) t;
            Map<String, Object> result = new HashMap<>();
            result.put("type", "command");
            result.put("command", commandObject(cmd.getCommand()));
            result.put("response", responseObject(cmd.getResponse()));
            return result;
        }
        return null;
    }
}
