/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.churchkey.util;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.function.Function;

import static java.lang.ClassLoader.getSystemClassLoader;

public class Utils {
    private static final Function<String, byte[]> HEX_PARSER;
    private static final Function<byte[], String> HEX_WRITER;
    static {
        Function<String, byte[]> parser;
        Function<byte[], String> writer;
        try {
            final Class<?> hexFormat = getSystemClassLoader().loadClass("java.util.HexFormat");
            final Method of = hexFormat.getMethod("of");
            if (!of.isAccessible()) {
                of.setAccessible(true);
            }
            final Object instance = of.invoke(null);
            final Method parseHex = hexFormat.getMethod("parseHex", CharSequence.class);
            if (!parseHex.isAccessible()) {
                parseHex.setAccessible(true);
            }
            final Method formatHex = hexFormat.getMethod("formatHex", byte[].class);
            if (!formatHex.isAccessible()) {
                formatHex.setAccessible(true);
            }
            parser = s -> {
                try {
                    return byte[].class.cast(parseHex.invoke(instance, s));
                } catch (final IllegalAccessException e) {
                    throw new IllegalStateException(e);
                } catch (final InvocationTargetException e) {
                    final Throwable ex = e.getTargetException();
                    if (RuntimeException.class.isInstance(ex)) {
                        throw RuntimeException.class.cast(ex);
                    }
                    throw new IllegalStateException(ex);
                }
            };
            writer = bytes -> {
                try {
                    return String.class.cast(formatHex.invoke(instance, bytes));
                } catch (final IllegalAccessException e) {
                    throw new IllegalStateException(e);
                } catch (final InvocationTargetException e) {
                    final Throwable ex = e.getTargetException();
                    if (RuntimeException.class.isInstance(ex)) {
                        throw RuntimeException.class.cast(ex);
                    }
                    throw new IllegalStateException(ex);
                }
            };
        } catch (final Exception cnfe) {
            // DO NOT USE METHOD REF to keep it lazy!
            parser = s -> org.tomitribe.util.Hex.fromString(s);
            writer = s -> org.tomitribe.util.Hex.toString(s);
        }
        HEX_PARSER = parser;
        HEX_WRITER = writer;
    }

    private Utils() {
    }

    public static boolean startsWith(final String prefix, final byte[] bytes) {
        final byte[] prefixBytes = prefix.getBytes();

        return startsWith(bytes, prefixBytes);
    }

    public static boolean startsWith(final byte[] bytes, final byte[] prefixBytes) {
        if (bytes.length < prefixBytes.length) return false;

        for (int i = 0; i < prefixBytes.length; i++) {
            if (prefixBytes[i] != bytes[i]) return false;
        }

        return true;
    }

    public static byte[] fromHexString(final String s) {
        return HEX_PARSER.apply(s);
    }

    public static String toHexString(final byte[] bytes) {
        return HEX_WRITER.apply(bytes);
    }
}
