/*
 * Copyright 2016-2023 the original author or authors.
 * Taken from https://github.com/junit-pioneer/junit-pioneer/blob/98cef28462c8b7ab66231cc5b7e8daef3b329f67/src/main/java/org/junitpioneer/jupiter/ExpectedToFailExtension.java
 *
 * All rights reserved. This program and the accompanying materials are
 * made available under the terms of the Eclipse Public License v2.0 which
 * accompanies this distribution and is available at
 *
 * http://www.eclipse.org/legal/epl-v20.html
 */

package cz.crcs.ectester.reader;

import java.lang.reflect.Method;
import java.util.stream.Stream;

import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionConfigurationException;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.junit.platform.commons.support.AnnotationSupport;
import org.opentest4j.AssertionFailedError;
import org.opentest4j.TestAbortedException;

class XFailExtension implements Extension, InvocationInterceptor {

    @Override
    public void interceptTestMethod(Invocation<Void> invocation, ReflectiveInvocationContext<Method> invocationContext,
                                    ExtensionContext extensionContext) throws Throwable {
        invokeAndInvertResult(invocation, extensionContext);
    }

    private static void invokeAndInvertResult(Invocation<Void> invocation, ExtensionContext extensionContext)
            throws Throwable {
        XFail expectedToFail = getExpectedToFailAnnotation(extensionContext);
        if (expectedToFail.withExceptions().length == 0) {
            throw new ExtensionConfigurationException("@XFail withExceptions must not be empty");
        }

        try {
            invocation.proceed();
            // at this point, the invocation succeeded, so we'd want to call `fail(...)`,
            // but that would get handled by the following `catch` and so it's easier
            // to instead fall through to a `fail(...)` after the `catch` block
        }
        catch (Throwable t) {
            if (shouldPreserveException(t)) {
                throw t;
            }

            if (Stream.of(expectedToFail.withExceptions()).noneMatch(clazz -> clazz.isInstance(t))) {
                throw new AssertionFailedError(
                        "Test marked as temporarily 'expected to fail' failed with an unexpected exception", t);
            }

            String message = expectedToFail.value();
            if (message.isEmpty()) {
                message = "Test marked as temporarily 'expected to fail' failed as expected";
            }

            throw new TestAbortedException(message, t);
        }
    }

    /**
     * Returns whether the exception should be preserved and reported as is instead
     * of considering it an 'expected to fail' exception.
     *
     * <p>This method is used for exceptions that abort test execution and should
     * have higher precedence than aborted exceptions thrown by this extension.</p>
     */
    private static boolean shouldPreserveException(Throwable t) {
        // Note: Ideally would use the same logic JUnit uses to determine if exception is aborting
        // execution, see its class OpenTest4JAndJUnit4AwareThrowableCollector
        return t instanceof TestAbortedException;
    }

    private static XFail getExpectedToFailAnnotation(ExtensionContext context) {
        return AnnotationSupport
                .findAnnotation(context.getRequiredTestMethod(), XFail.class)
                .orElseThrow(() -> new IllegalStateException("@XFail is missing."));

    }

}