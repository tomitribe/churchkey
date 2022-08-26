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
package io.churchkey.util;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.function.Supplier;

public final class Printers {
    private static final Supplier<PrintStream> FACTORY;
    static {
        Supplier<PrintStream> factory;
        try {
            final Constructor<? extends PrintStream> constructor = Printers.class.getClassLoader()
                    .loadClass("org.tomitribe.util.PrintString")
                    .asSubclass(PrintStream.class)
                    .getConstructor();
            factory = () -> {
                try {
                    return constructor.newInstance();
                } catch (final InstantiationException | IllegalAccessException e) {
                    throw new IllegalStateException(e);
                } catch (final InvocationTargetException e) {
                    final Throwable ex = e.getTargetException();
                    if (RuntimeException.class.isInstance(ex)) {
                        throw RuntimeException.class.cast(ex);
                    }
                    throw new IllegalStateException(ex);
                }
            };
        } catch (final Error | Exception e) {
            factory = SimplePrinter::new;
        }
        FACTORY = factory;
    }

    private Printers() {
        // no-op
    }

    public static PrintStream printer() {
        return FACTORY.get();
    }

    private static class SimplePrinter extends PrintStream {
        public SimplePrinter() {
            super(new ByteArrayOutputStream(), true);
        }

        @Override
        public String toString() {
            flush();
            return out.toString();
        }
    }
}
