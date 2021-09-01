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
package org.tomitribe.churchkey.asn1;

import java.io.IOException;
import java.util.function.Function;

class Utils {
    public static final byte[] EMPTY_BYTE_ARRAY = {};
    public static final char EMPTY_HEX_SEPARATOR = '\0';
    public static final String HEX_DIGITS = "0123456789abcdef";

    private Utils() {
    }

    public static int length(byte... a) {
        return (a == null) ? 0 : a.length;
    }

    /**
     * @param  buf A buffer holding a 32-bit unsigned integer in <B>big endian</B> format. <B>Note:</B> if more than 4
     *             bytes are available, then only the <U>first</U> 4 bytes in the buffer will be used
     * @return The result as a {@code long} whose 32 high-order bits are zero
     * @see        #getUInt(byte[], int, int)
     */
    public static long getUInt(byte... buf) {
        return getUInt(buf, 0, length(buf));
    }

    /**
     * @param  buf A buffer holding a 32-bit unsigned integer in <B>big endian</B> format.
     * @param  off The offset of the data in the buffer
     * @param  len The available data length. <B>Note:</B> if more than 4 bytes are available, then only the
     *             <U>first</U> 4 bytes in the buffer will be used (starting at the specified <tt>offset</tt>)
     * @return The result as a {@code long} whose 32 high-order bits are zero
     */
    public static long getUInt(byte[] buf, int off, int len) {
        if (len < Integer.BYTES) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + Integer.BYTES + ", available=" + len);
        }

        long l = (buf[off] << 24) & 0xff000000L;
        l |= (buf[off + 1] << 16) & 0x00ff0000L;
        l |= (buf[off + 2] << 8) & 0x0000ff00L;
        l |= (buf[off + 3]) & 0x000000ffL;
        return l;
    }

    public static void checkTrue(boolean flag, String message, long value) {
        if (!flag) {
            throwIllegalArgumentException(message, value);
        }
    }

    public static void throwIllegalArgumentException(String format, Object... args) {
        throw createFormattedException(IllegalArgumentException::new, format, args);
    }

    public static <T extends Throwable> T createFormattedException(
            Function<? super String, ? extends T> constructor, String format, Object... args) {
        String message = String.format(format, args);
        return constructor.apply(message);
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  value                    The 32-bit value
     * @param  buf                      The buffer
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     * @see                             #putUInt(long, byte[], int, int)
     */
    public static int putUInt(long value, byte[] buf) {
        return putUInt(value, buf, 0, length(buf));
    }

    /**
     * Writes a 32-bit value in network order (i.e., MSB 1st)
     *
     * @param  value                    The 32-bit value
     * @param  buf                      The buffer
     * @param  off                      The offset to write the value
     * @param  len                      The available space
     * @return The number of bytes used in the buffer
     * @throws IllegalArgumentException if not enough space available
     */
    public static int putUInt(long value, byte[] buf, int off, int len) {
        if (len < Integer.BYTES) {
            throw new IllegalArgumentException("Not enough data for a UINT: required=" + Integer.BYTES + ", available=" + len);
        }

        buf[off] = (byte) ((value >> 24) & 0xFF);
        buf[off + 1] = (byte) ((value >> 16) & 0xFF);
        buf[off + 2] = (byte) ((value >> 8) & 0xFF);
        buf[off + 3] = (byte) (value & 0xFF);

        return Integer.BYTES;
    }

    public static int hashCode(byte[] a, int offset, int len) {
        if (len == 0) {
            return 0;
        }

        int result = 1;
        for (int pos = offset, count = 0; count < len; pos++, count++) {
            byte element = a[pos];
            result = 31 * result + element;
        }

        return result;
    }

    public static int diffOffset(byte[] a1, int startPos1, byte[] a2, int startPos2, int len) {
        for (int pos1 = startPos1, pos2 = startPos2, count = 0; count < len; pos1++, pos2++, count++) {
            byte v1 = a1[pos1];
            byte v2 = a2[pos2];
            if (v1 != v2) {
                return count;
            }
        }

        return -1;
    }

    public static String toHex(byte[] array, int offset, int len, char sep) {
        if (len <= 0) {
            return "";
        }

        try {
            return appendHex(new StringBuilder(len * 3 /* 2 HEX + sep */), array, offset, len, sep).toString();
        } catch (IOException e) { // unexpected
            return e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public static <A extends Appendable> A appendHex(
            A sb, byte[] array, int offset, int len, char sep)
            throws IOException {
        if (len <= 0) {
            return sb;
        }

        for (int curOffset = offset, maxOffset = offset + len; curOffset < maxOffset; curOffset++) {
            byte b = array[curOffset];
            if ((curOffset > offset) && (sep != EMPTY_HEX_SEPARATOR)) {
                sb.append(sep);
            }
            sb.append(HEX_DIGITS.charAt((b >> 4) & 0x0F));
            sb.append(HEX_DIGITS.charAt(b & 0x0F));
        }

        return sb;
    }

    public static int length(CharSequence cs) {
        return cs == null ? 0 : cs.length();
    }

    public static boolean isEmpty(CharSequence cs) {
        return length(cs) <= 0;
    }

    @SafeVarargs
    public static <T> int length(T... a) {
        return (a == null) ? 0 : a.length;
    }
}
