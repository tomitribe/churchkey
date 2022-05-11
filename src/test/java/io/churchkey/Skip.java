/*
 * Copyright 2021 Tomitribe and community
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.churchkey;

import org.junit.Assume;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;
import java.util.List;

/**
 * Ignores the parameterized test if the portion of the description
 * inside "[]" matches one of the values of the annotation
 *
 * For example, given the description "oid[Oakley-EC2N-3]", the following
 * annotation would cause the execution to be skipped
 *
 * (at)IgnoreIf("Oakley-EC2N-3")
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@Inherited
public @interface Skip {

    String[] value();

    class Rule implements TestRule {

        @Override
        public Statement apply(Statement base, Description description) {
            return new IgnorableStatement(base, description);
        }

        private static class IgnorableStatement extends Statement {

            private final Statement base;

            private final Description description;

            public IgnorableStatement(final Statement base, final Description description) {
                this.base = base;
                this.description = description;
            }

            @Override
            public void evaluate() throws Throwable {
                final Skip annotation = description.getAnnotation(Skip.class);
                final String displayName = description.getDisplayName();
                if (annotation != null && displayName.contains("[")) {
                    final String params = displayName.replaceAll(".*?\\[(.*?)].*", "$1");
                    final List<String> skip = Arrays.asList(annotation.value());
                    Assume.assumeTrue("Test is ignored!", !skip.contains(params));
                }
                base.evaluate();
            }
        }
    }
}