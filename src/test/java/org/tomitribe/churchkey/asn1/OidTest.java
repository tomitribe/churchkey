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

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class OidTest {

    @Test
    public void testToString() {
        final Oid oid = new Oid(1, 2, 840, 113549, 1, 1, 1);
        assertEquals("1.2.840.113549.1.1.1", oid.toString());
    }

    @Test
    public void toBytesRsaOid() {
        final Oid oid = new Oid(1, 2, 840, 113549, 1, 1, 1);
        final byte[] bytes = oid.toBytes();
        assertArrayEquals(new byte[]{42, -122, 72, -122, -9, 13, 1, 1, 1}, bytes);
    }

    @Test
    public void shifting() throws Exception {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int elem = 840;
        bytes.write(elem & 0x7F);
        elem = elem >> 7;
        while (elem > 0) {
            bytes.write((byte) (elem | 0x80));
            elem = elem >> 7;
        }

    }

    @Test
    public void shifting2() throws Exception {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int elem = 840;

        byte b4 = (byte) (elem & 0x7F);

        elem = elem >> 7;
        byte b3 = (byte) (elem | 0x80);

        elem = elem >> 7;
        if (elem <= 0) {
            bytes.write(b3);
            bytes.write(b4);
            return;
        }

        byte b2 = (byte) (elem | 0x80);
        elem = elem >> 7;
        if (elem <= 0) {
            bytes.write(b2);
            bytes.write(b3);
            bytes.write(b4);
            return;
        }

        byte b1 = (byte) (elem | 0x80);
        elem = elem >> 7;
        if (elem <= 0) {
            bytes.write(b1);
            bytes.write(b2);
            bytes.write(b3);
            bytes.write(b4);
            return;
        }

        byte b0 = (byte) (elem | 0x80);
        elem = elem >> 7;
        if (elem <= 0) {
            bytes.write(b0);
            bytes.write(b1);
            bytes.write(b2);
            bytes.write(b3);
            bytes.write(b4);
            return;
        }

        System.out.println();
    }

    @Test
    public void shifting3() throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] bytes = new byte[5];
        int pos = bytes.length - 1;
        int elem = 840;

        bytes[pos--] = (byte) (elem & 0x7F);
        elem = elem >> 7;
        while (elem > 0) {
            bytes[pos--] = (byte) (elem | 0x80);
            elem = elem >> 7;
        }
        pos++;
        final int length = bytes.length - pos;
        out.write(bytes, pos, length);
        System.out.println();
    }

    @Test
    public void fromBytes() throws IOException {
        //1.2.840.113549.1.1.1
        final Oid oid = Oid.from(new byte[]{42, -122, 72, -122, -9, 13, 1, 1, 1});

        int i = 0;
        assertEquals(1, oid.get(i++));
        assertEquals(2, oid.get(i++));
        assertEquals(840, oid.get(i++));
        assertEquals(113549, oid.get(i++));
        assertEquals(1, oid.get(i++));
        assertEquals(1, oid.get(i++));
        assertEquals(1, oid.get(i++));

        try {
            oid.get(i++);
            fail("expected no more elements");
        } catch (IndexOutOfBoundsException expected) {
            // pass
        }
    }


}
