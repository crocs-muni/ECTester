package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

import javax.smartcardio.CardException;
import java.util.Arrays;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class PerformanceTest extends SimpleTest<CommandTestable> {
    private CardMngr cardManager;
    private long[] times;
    private long[] reducedTimes;
    private Response[] responses;
    private long mean;
    private long median;
    private long mode;
    private int count;
    private String desc;

    private PerformanceTest(CardMngr cardManager, CommandTestable testable, int count, String desc) {
        super(testable, new TestCallback<CommandTestable>() {
            @Override
            public Result apply(CommandTestable testable) {
                return new Result(Result.Value.SUCCESS);
            }
        });
        this.cardManager = cardManager;
        this.count = count;
        this.desc = desc;
    }

    public static PerformanceTest repeat(CardMngr cardManager, Command cmd, int count) {
        return new PerformanceTest(cardManager, new CommandTestable(cmd), count, null);
    }

    public static PerformanceTest repeat(CardMngr cardManager, String desc, Command cmd, int count) {
        return new PerformanceTest(cardManager, new CommandTestable(cmd), count, desc);
    }

    @Override
    public String getDescription() {
        String rest = String.format("Mean = %d ns, Median = %d ns, Mode = %d ns", mean, median, mode);
        return (desc == null ? rest : desc + " (" + rest + ")");
    }

    @Override
    protected void runSelf() {
        long baseTime;
        try {
            new Command.SetDryRunMode(cardManager, ECTesterApplet.MODE_DRY_RUN).send();
            testable.run();
            baseTime = testable.getResponse().getDuration();
            testable.reset();
            testable.run();
            baseTime += testable.getResponse().getDuration();
            testable.reset();
            baseTime /= 2;
            new Command.SetDryRunMode(cardManager, ECTesterApplet.MODE_NORMAL).send();
        } catch (CardException ce) {
            throw new TestException(ce);
        }

        times = new long[count];
        reducedTimes = new long[count];
        responses = new Response[count];
        for (int i = 0; i < count; ++i) {
            testable.run();
            responses[i] = testable.getResponse();
            times[i] = responses[i].getDuration();
            reducedTimes[i] = times[i] - baseTime;
            testable.reset();
        }

        mean = Arrays.stream(reducedTimes).sum() / count;

        long[] sorted = reducedTimes.clone();
        Arrays.sort(sorted);
        if (count % 2 == 0) {
            median = (sorted[(count / 2) - 1] + sorted[count / 2]) / 2;
        } else {
            median = sorted[count / 2];
        }

        long max_occurences = 0;
        int i = 0;
        while (i < count) {
            long current_value = sorted[i];
            long current_occurences = 0;
            while (i < count && sorted[i] == current_value) {
                i++;
                current_occurences++;
            }
            if (current_occurences > max_occurences) {
                max_occurences = current_occurences;
                mode = current_value;
            }
        }
        result = callback.apply(testable);
    }

    public long getCount() {
        return count;
    }

    public Command getCommand() {
        return testable.getCommand();
    }

    public Response[] getResponses() {
        return responses;
    }

    public long[] getTimes() {
        return times;
    }

    public long[] getReducedTimes() {
        return reducedTimes;
    }

    public long getMean() {
        return mean;
    }

    public long getMedian() {
        return median;
    }

    public long getMode() {
        return mode;
    }
}
