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

    // (0x100+val1) % 0x100
    public byte[] toBytes() {

        final Iterator<Integer> values = oid.iterator();
        final Integer one = values.next();
        final Integer two = values.next();

        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        int val1 = one * 40 + two;
        out.write(val1);

        while (values.hasNext()) {
            int elem = values.next();

            if (elem <= 0x7F) {
                out.write(elem);
            } else {
                final byte[] bytes = new byte[5];
                int pos = bytes.length - 1;

                bytes[pos--] = (byte) (elem & 0x7F);
                elem = elem >> 7;
                while (elem > 0) {
                    bytes[pos--] = (byte) (elem | 0x80);
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
        int vLen = bytes.length;
        if (vLen <= 0) {
            throw new EOFException("Not enough data for an OID");
        }

        List<Integer> oid = new ArrayList<>(vLen + 1);
        int val1 = bytes[0] & 0xFF;
        oid.add(Integer.valueOf(val1 / 40));
        oid.add(Integer.valueOf(val1 % 40));

        for (int curPos = 1; curPos < vLen; curPos++) {
            int v = bytes[curPos] & 0xFF;
            if (v <= 0x7F) { // short form
                oid.add(Integer.valueOf(v));
                continue;
            }

            long curVal = v & 0x7F;
            curPos++;

            for (int subLen = 1; ; subLen++, curPos++) {
                if (curPos >= vLen) {
                    throw new EOFException("Incomplete OID value");
                }

                if (subLen > 5) { // 32 bit values can span at most 5 octets
                    throw new StreamCorruptedException("OID component encoding beyond 5 bytes");
                }

                v = bytes[curPos] & 0xFF;
                curVal = ((curVal << 7) & 0xFFFFFFFF80L) | (v & 0x7FL);
                if (curVal > Integer.MAX_VALUE) {
                    throw new StreamCorruptedException("OID value exceeds 32 bits: " + curVal);
                }

                if (v <= 0x7F) { // found last octet ?
                    break;
                }
            }

            oid.add(Integer.valueOf((int) (curVal & 0x7FFFFFFFL)));
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
