package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.reader.command.Command;

import java.util.Arrays;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class PerformanceTest extends SimpleTest<CommandTestable> {
    private long[] times;
    private long mean;
    private long median;
    private long mode;
    private int count;

    private PerformanceTest(CommandTestable testable, int count) {
        super(testable, new TestCallback<CommandTestable>() {
            @Override
            public Result apply(CommandTestable testable) {
                return new Result(Result.Value.SUCCESS);
            }
        });
        this.count = count;
    }

    public static PerformanceTest repeat(Command cmd, int count) {
        return new PerformanceTest(new CommandTestable(cmd), count);
    }

    @Override
    public String getDescription() {
        return String.format("Mean = %d ns, Median = %d ns, Mode = %d ns", mean, median, mode);
    }

    @Override
    protected void runSelf() {
        times = new long[count];
        for (int i = 0; i < count; ++i) {
            testable.run();
            times[i] = testable.getResponse().getDuration();
            testable.reset();
        }

        mean = Arrays.stream(times).sum() / count;

        long[] sorted = times.clone();
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

    public long[] getTimes() {
        return times;
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
