package cz.crcs.ectester.common.test;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * A compound test that runs many Tests and has a Result dependent on all/some of their Results.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CompoundTest extends Test implements Cloneable {
    private Function<Test[], Result> resultCallback;
    private Consumer<Test[]> runCallback;
    private Test[] tests;
    private String description = "";

    private final static Consumer<Test[]> RUN_ALL = tests -> {
        for (Test t : tests) {
            t.run();
        }
    };

    private final static Consumer<Test[]> RUN_GREEDY_ALL = tests -> {
        for (Test t : tests) {
            t.run();
            if (!t.ok()) {
                break;
            }
        }
    };

    private final static Consumer<Test[]> RUN_GREEDY_ANY = tests -> {
        for (Test t : tests) {
            t.run();
            if (t.ok()) {
                break;
            }
        }
    };

    private CompoundTest(Function<Test[], Result> resultCallback, Consumer<Test[]> runCallback, Test... tests) {
        this.resultCallback = resultCallback;
        this.runCallback = runCallback;
        this.tests = Arrays.stream(tests).filter(Objects::nonNull).toArray(Test[]::new);
    }

    private CompoundTest(Function<Test[], Result> callback, Consumer<Test[]> runCallback, String descripiton, Test... tests) {
        this(callback, runCallback, tests);
        this.description = descripiton;
    }

    public static CompoundTest function(Function<Test[], Result> callback, Test... tests) {
        return new CompoundTest(callback, RUN_ALL, tests);
    }

    public static CompoundTest function(Function<Test[], Result> callback, Consumer<Test[]> runCallback, Test... tests) {
        return new CompoundTest(callback, runCallback, tests);
    }

    public static CompoundTest function(Function<Test[], Result> callback, String description, Test... tests) {
        return new CompoundTest(callback, RUN_ALL, description, tests);
    }

    public static CompoundTest function(Function<Test[], Result> callback, Consumer<Test[]> runCallback, String description, Test... tests) {
        return new CompoundTest(callback, runCallback, description, tests);
    }

    private static CompoundTest expectAll(Result.ExpectedValue what, Consumer<Test[]> runCallback, Test[] all) {
        return new CompoundTest((tests) -> {
            for (Test test : tests) {
                if (!Result.Value.fromExpected(what, test.ok()).ok()) {
                    return new Result(Result.Value.FAILURE, "Some sub-tests did not have the expected result.");
                }
            }
            return new Result(Result.Value.SUCCESS, "All sub-tests had the expected result.");
        }, runCallback, all);
    }

    public static CompoundTest all(Result.ExpectedValue what, Test... all) {
        return expectAll(what, RUN_ALL, all);
    }

    public static CompoundTest all(Result.ExpectedValue what, String description, Test... all) {
        CompoundTest result = CompoundTest.all(what, all);
        result.setDescription(description);
        return result;
    }

    public static CompoundTest greedyAll(Result.ExpectedValue what, Test... all) {
        return expectAll(what, RUN_GREEDY_ALL, all);
    }

    public static CompoundTest greedyAll(Result.ExpectedValue what, String description, Test... all) {
        CompoundTest result = CompoundTest.greedyAll(what, all);
        result.setDescription(description);
        return result;
    }

    public static CompoundTest greedyAllTry(Result.ExpectedValue what, Test... all) {
        return new CompoundTest((tests) -> {
            int run = 0;
            int ok = 0;
            for (Test test : tests) {
                if (test.hasRun()) {
                    run++;
                    if (Result.Value.fromExpected(what, test.ok()).ok()) {
                        ok++;
                    }
                }
            }
            if (run == tests.length) {
                if (ok == run) {
                    return new Result(Result.Value.SUCCESS, "All sub-tests had the expected result.");
                } else {
                    return new Result(Result.Value.FAILURE, "Some sub-tests did not have the expected result.");
                }
            } else {
                return new Result(Result.Value.SUCCESS, "All considered sub-tests had the expected result.");
            }
        }, RUN_GREEDY_ALL, all);
    }

    public static CompoundTest greedyAllTry(Result.ExpectedValue what, String description, Test... all) {
        CompoundTest result = CompoundTest.greedyAllTry(what, all);
        result.setDescription(description);
        return result;
    }

    private static CompoundTest expectAny(Result.ExpectedValue what, Consumer<Test[]> runCallback, Test[] any) {
        return new CompoundTest((tests) -> {
            for (Test test : tests) {
                if (Result.Value.fromExpected(what, test.ok()).ok()) {
                    return new Result(Result.Value.SUCCESS, "Some sub-tests did have the expected result.");
                }
            }
            return new Result(Result.Value.FAILURE, "None of the sub-tests had the expected result.");
        }, runCallback, any);
    }

    public static CompoundTest greedyAny(Result.ExpectedValue what, Test... any) {
        return expectAny(what, RUN_GREEDY_ANY, any);
    }

    public static CompoundTest greedyAny(Result.ExpectedValue what, String description, Test... any) {
        CompoundTest result = CompoundTest.greedyAny(what, any);
        result.setDescription(description);
        return result;
    }

    public static CompoundTest any(Result.ExpectedValue what, Test... any) {
        return expectAny(what, RUN_ALL, any);
    }

    public static CompoundTest any(Result.ExpectedValue what, String description, Test... any) {
        CompoundTest result = CompoundTest.any(what, any);
        result.setDescription(description);
        return result;
    }

    public static CompoundTest mask(Result.ExpectedValue[] results, Test... masked) {
        return new CompoundTest((tests) -> {
            for (int i = 0; i < results.length; ++i) {
                if (!Result.Value.fromExpected(results[i], tests[i].ok()).ok()) {
                    return new Result(Result.Value.FAILURE, "Some sub-tests did not match the result mask.");
                }
            }
            return new Result(Result.Value.SUCCESS, "All sub-tests matched the expected mask.");
        }, RUN_ALL, masked);
    }

    public static CompoundTest mask(Result.ExpectedValue[] results, String description, Test... masked) {
        CompoundTest result = CompoundTest.mask(results, masked);
        result.setDescription(description);
        return result;
    }

    public Test[] getTests() {
        return tests.clone();
    }

    public Test[] getRunTests() {
        return Arrays.stream(tests).filter(Test::hasRun).toArray(Test[]::new);
    }

    public Test[] getStartedTests() {
        return Arrays.stream(tests).filter(Test::hasStarted).toArray(Test[]::new);
    }

    public Test[] getSkippedTests() {
        return Arrays.stream(tests).filter((test) -> !test.hasRun()).toArray(Test[]::new);
    }

    @Override
    protected void runSelf() {
        runCallback.accept(tests);
        result = resultCallback.apply(tests);
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public CompoundTest clone() throws CloneNotSupportedException {
        return (CompoundTest) super.clone();
    }
}
