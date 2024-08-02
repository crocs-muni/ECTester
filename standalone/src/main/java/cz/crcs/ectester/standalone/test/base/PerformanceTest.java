package cz.crcs.ectester.standalone.test.base;

import cz.crcs.ectester.common.test.BaseTestable;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.standalone.libs.ProviderECLibrary;

import java.util.Arrays;

/**
 * @author David Hofman
 */
public class PerformanceTest extends SimpleTest<BaseTestable> {

    private final ProviderECLibrary library;
    private long[] times;
    private long mean;
    private long median;
    private long mode;
    private final int count;
    private final String desc;

    private PerformanceTest(BaseTestable testable, ProviderECLibrary library, int count, String desc) {
        super(testable, new TestCallback<BaseTestable>() {
            @Override
            public Result apply(BaseTestable testable) {
                return new Result(Result.Value.SUCCESS);
            }
        });
        this.library = library;
        this.count = count;
        this.desc = desc;
    }

    public static PerformanceTest repeat(BaseTestable testable, ProviderECLibrary library, int count) {
        return new PerformanceTest(testable, library, count, null);
    }

    public static PerformanceTest repeat(BaseTestable testable, ProviderECLibrary library, String desc, int count) {
        return new PerformanceTest(testable, library, count, desc);
    }

    @Override
    public String getDescription() {
        String rest = String.format("Mean = %d ns, Median = %d ns, Mode = %d ns", mean, median, mode);
        return (desc == null ? rest : desc + " (" + rest + ")");
    }

    @Override
    protected void runSelf() {

        times = new long[count];
        for (int i = 0; i < count; ++i) {
            times[i] = measureTime();
        }

        mean = Arrays.stream(times).sum() / count;

        long[] sorted = times.clone();
        Arrays.sort(sorted);
        if (count % 2 == 0) {
            median = (sorted[(count / 2) - 1] + sorted[count / 2]) / 2;
        } else {
            median = sorted[count / 2];
        }

        long max_occurrences = 0;
        int i = 0;
        while (i < count) {
            long current_value = sorted[i];
            long current_occurrences = 0;
            while (i < count && sorted[i] == current_value) {
                i++;
                current_occurrences++;
            }
            if (current_occurrences > max_occurrences) {
                max_occurrences = current_occurrences;
                mode = current_value;
            }
        }
        result = callback.apply(testable);
    }

    public long getCount() {
        return count;
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

    private long measureTime() {
        if (testable.hasRun()) {
            testable.reset();
        }
        if (library.getNativeTimingSupport().isEmpty()) {
            long startTime = System.nanoTime();
            testable.run();
            return System.nanoTime() - startTime;
        } else {
            testable.run();
            return library.getLastNativeTiming();
        }
    }
}
