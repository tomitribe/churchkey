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
package org.tomitribe.churchkey.asn1;

import org.tomitribe.util.Hex;
import org.tomitribe.util.Join;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.StreamCorruptedException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * OIDs are encoded using Variable-Length Quantity.
 *
 * Good resources for understanding OID encoding
 *
 * https://en.wikipedia.org/wiki/Variable-length_quantity
 * https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier?redirectedfrom=MSDN
 */
public class Oid {

    final List<Integer> oid = new ArrayList<>();

    public Oid(final int... oid) {
        for (final int i : oid) {
            this.oid.add(i);
        }
    }

    public Oid(final List<Integer> oid) {
        this.oid.addAll(oid);
    }

    public int length() {
        return oid.size();
    }

    public int get(int index) {
        return oid.get(index);
    }

    public List<Integer> getComponents() {
        return Collections.unmodifiableList(oid);
    }

    @Override
    public String toString() {
        return Join.join(".", oid);
    }

    public String toHex() {
        return Hex.toString(toBytes());
    }

    public byte[] toBytes() {

        final Iterator<Integer> values = oid.iterator();
        final Integer one = values.next();
        final Integer two = values.next();

        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        int val1 = one * 40 + two;
        out.write(val1);

        while (values.hasNext()) {
            int elem = values.next();

            if (elem <= 0b1111111) {
                out.write(elem);
            } else {
                final byte[] bytes = new byte[5];
                int pos = bytes.length - 1;

                bytes[pos--] = (byte) (elem & 0b1111111);
                elem = elem >> 7;
                while (elem > 0) {
                    bytes[pos--] = (byte) (elem | 0b10000000);
                    elem = elem >> 7;
                }
                pos++;
                final int length = bytes.length - pos;
                out.write(bytes, pos, length);
            }
        }
        return out.toByteArray();
    }

    public static Oid fromString(final String dottedIntegers) throws IOException {
        final String[] strings = dottedIntegers.split("\\.");
        final List<Integer> integers = Stream.of(strings)
                .map(Integer::valueOf)
                .collect(Collectors.toList());
        return new Oid(integers);
    }

    public static Oid fromHex(final String hex) throws IOException {
        final byte[] bytes = Hex.fromString(hex);
        return fromBytes(bytes);
    }

    public static Oid fromBytes(final byte[] bytes) throws IOException {
        final int length = bytes.length;
        if (length <= 0) {
            throw new EOFException("Not enough data for an OID");
        }

        /*
         * Java bytes are signed (-128 to 127).
         * We need unsigned values (0 to 255)
         */
        final int toPositiveNumber = 0b11111111;

        /*
         * Anything 7 bits or under is valid as a
         * short form (not encoded) number
         */
        final int shortForm = 0b01111111;

        final List<Integer> oid = new ArrayList<>(length + 1);

        /*
         * The first value is treated specially.  The first
         * to values of the OID are encoded in it using
         * the rule below.  This only works because there
         * are limits on how big these two numbers can be.
         */
        final int firstValue = bytes[0] & toPositiveNumber;
        oid.add(Integer.valueOf(firstValue / 40));
        oid.add(Integer.valueOf(firstValue % 40));

        /*
         * Now read each subsequent OID value from the remaining bytes
         */
        for (int position = 1; position < length; position++) {
            int b = bytes[position] & toPositiveNumber;

            /*
             * If the value can fit into 7 bits, we can simply
             * use it as-is.
             */
            if (b <= shortForm) { // short form
                oid.add(Integer.valueOf(b));
                continue;
            }

            /*
             * The value cannot fit into 7 bits, so we need
             * to read the next byte, chop off the 8th bit
             * so it is also 7 bits, then shift those 7
             * bits onto the value we just read.
             *
             * This can happen at most 5 times (for 5 bytes)
             * because OID numbers can only be 32 bits max.
             *
             * Basically we'll build the number 7 bits at a time
             * reading at most 5 bytes in the process.
             */
            long value = b & shortForm;
            position++;

            for (int subLen = 1; ; subLen++, position++) {
                if (position >= length) {
                    throw new EOFException("Incomplete OID value");
                }

                if (subLen > 5) { // 32 bit values can span at most 5 octets
                    throw new StreamCorruptedException("OID component encoding beyond 5 bytes");
                }

                b = bytes[position] & toPositiveNumber;
                value = (value << 7) | b;
                if (value > Integer.MAX_VALUE) {
                    // 7 * 5 = 35
                    // This means we could potentially get a 35-bit number
                    throw new StreamCorruptedException("OID value exceeds 32 bits: " + value);
                }

                if (b <= shortForm) { // found last octet ?
                    break;
                }
            }

            oid.add(Integer.valueOf((int) value));
        }

        return new Oid(oid);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final Oid oid1 = (Oid) o;

        if (!oid.equals(oid1.oid)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return oid.hashCode();
    }
}
