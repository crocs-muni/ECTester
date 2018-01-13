package cz.crcs.ectester.common.test;

import java.util.function.Function;

/**
 * A compound test that runs many Tests and has a Result dependent on all/some of their Results.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CompoundTest extends Test {
    private Function<Test[], Result> callback;
    private Test[] tests;
    private String description;

    private CompoundTest(Function<Test[], Result> callback, Test... tests) {
        this.callback = callback;
        this.tests = tests;
    }

    private CompoundTest(Function<Test[], Result> callback, String descripiton, Test... tests) {
        this(callback, tests);
        this.description = descripiton;
    }

    public static CompoundTest function(Function<Test[], Result> callback, Test... tests) {
        return new CompoundTest(callback, tests);
    }

    public static CompoundTest function(Function<Test[], Result> callback, String description, Test... tests) {
        return new CompoundTest(callback, description, tests);
    }

    public static CompoundTest all(Result.ExpectedValue what, Test... all) {
        return new CompoundTest((tests) -> {
            for (Test test : tests) {
                if (!Result.Value.fromExpected(what, test.ok()).ok()) {
                    return new Result(Result.Value.FAILURE, "Some sub-tests did not have the expected result.");
                }
            }
            return new Result(Result.Value.SUCCESS, "All sub-tests had the expected result.");
        }, all);
    }

    public static CompoundTest all(Result.ExpectedValue what, String description, Test... all) {
        CompoundTest result = CompoundTest.all(what, all);
        result.setDescription(description);
        return result;
    }

    public static CompoundTest any(Result.ExpectedValue what, Test... any) {
        return new CompoundTest((tests) -> {
            for (Test test : tests) {
                if (Result.Value.fromExpected(what, test.ok()).ok()) {
                    return new Result(Result.Value.SUCCESS, "Some sub-tests did have the expected result.");
                }
            }
            return new Result(Result.Value.FAILURE, "None of the sub-tests had the expected result.");
        }, any);
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
        }, masked);
    }

    public static CompoundTest mask(Result.ExpectedValue[] results, String description, Test... masked) {
        CompoundTest result = CompoundTest.mask(results, masked);
        result.setDescription(description);
        return result;
    }

    public Test[] getTests() {
        return tests;
    }

    @Override
    public void run() throws TestException {
        if (hasRun)
            return;

        for (Test test : tests) {
            test.run();
        }

        result = callback.apply(tests);
        this.hasRun = true;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String getDescription() {
        return description;
    }
}
