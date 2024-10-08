/*
 * Copyright 2016-2023 the original author or authors.
 * Taken from https://github.com/junit-pioneer/junit-pioneer/blob/98cef28462c8b7ab66231cc5b7e8daef3b329f67/src/main/java/org/junitpioneer/jupiter/ExpectedToFail.java
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v2.0 which
 * accompanies this distribution and is available at
 *
 * http://www.eclipse.org/legal/epl-v20.html
 */

package cz.crcs.ectester.reader;

import static java.lang.annotation.ElementType.ANNOTATION_TYPE;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.junit.jupiter.api.extension.ExtendWith;

/**
 * {@code @ExpectedToFail} is a JUnit Jupiter extension to mark test methods as temporarily
 * 'expected to fail'. Such test methods will still be executed but when they result in a test
 * failure or error the test will be aborted. However, if the test method unexpectedly executes
 * successfully, it is marked as failure to let the developer know that the test is now
 * successful and that the {@code @ExpectedToFail} annotation can be removed.
 *
 * <p>The big difference compared to JUnit's {@link org.junit.jupiter.api.Disabled @Disabled}
 * annotation is that the developer is informed as soon as a test is successful again.
 * This helps to avoid creating duplicate tests by accident and counteracts the accumulation
 * of disabled tests over time.</p>
 *
 * <p>Further, the {@link #withExceptions()} attribute can be used to restrict the extension's behavior
 * to specific exceptions. That is, only if the test method ends up throwing one of the specified exceptions
 * will the test be aborted. This can, for example, be used when the production code temporarily throws
 * an {@link UnsupportedOperationException} because some feature has not been implemented yet, but the
 * test method is already implemented and should not fail on a failing assertion.
 * </p>
 *
 * <p>The annotation can only be used on methods and as meta-annotation on other annotation types.
 * Similar to {@code @Disabled}, it has to be used in addition to a "testable" annotation, such
 * as {@link org.junit.jupiter.api.Test @Test}. Otherwise the annotation has no effect.</p>
 *
 * <p><b>Important:</b> This annotation is <b>not</b> intended as a way to mark test methods
 * which intentionally cause exceptions. Such test methods should use
 * {@link org.junit.jupiter.api.Assertions#assertThrows(Class, org.junit.jupiter.api.function.Executable) assertThrows}
 * or similar means to explicitly test for a specific exception class being thrown by a
 * specific action.</p>
 *
 * <p>For more details and examples, see
 * <a href="https://junit-pioneer.org/docs/expected-to-fail-tests/" target="_top">the documentation on <code>@ExpectedToFail</code></a>.</p>
 *
 * @since 1.8.0
 * @see org.junit.jupiter.api.Disabled
 */
@Documented
@Retention(RUNTIME)
/*
 * Only supports METHOD and ANNOTATION_TYPE as targets but not test classes because there
 * it is not clear what the 'correct' behavior would be when only a few test methods
 * execute successfully. Would the developer then have to remove the @ExpectedToFail annotation
 * from the test class and annotate methods individually?
 */
@Target({ METHOD, ANNOTATION_TYPE })
@ExtendWith(XFailExtension.class)
public @interface XFail {

    /**
     * Defines the message to show when a test is aborted because it is failing.
     * This can be used for example to briefly explain why the tested code is not working
     * as intended at the moment.
     * An empty string (the default) causes a generic default message to be used.
     */
    String value() default "";

    /**
     * Specifies which exceptions are expected to be thrown and will cause the test to be aborted rather than fail.
     * An empty array is considered a configuration error and will cause the test to fail. Instead, consider leaving
     * the attribute set to the default value when any exception should cause the test to be aborted.
     */
    Class<? extends Throwable>[] withExceptions() default { Throwable.class };

}