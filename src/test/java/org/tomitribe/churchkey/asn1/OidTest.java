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
import org.tomitribe.util.Hex;

import java.io.IOException;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
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
    public void toBytes() {
        final Oid oid = new Oid(1, 2, 127, 128);
        final byte[] bytes = oid.toBytes();
        final String s = Hex.toString(bytes);
        assertEquals("2a7f8100", s);
    }

    @Test
    public void toBytes2() {
        final Oid oid = new Oid(1, 2, 8192, 16383);
        final byte[] bytes = oid.toBytes();
        final String s = Hex.toString(bytes);
        assertEquals("2ac000ff7f", s);
    }

    @Test
    public void toHex() {
        final Oid oid = new Oid(1, 2, 8192, 16383);
        final String s = oid.toHex();
        assertEquals("2ac000ff7f", s);
    }

    @Test
    public void equals() {
        {
            final Oid a = new Oid(1, 3, 8192, 16383);
            final Oid b = new Oid(1, 3, 8192, 16383);
            assertEquals(a, b);
        }
        {
            final Oid a = new Oid(1, 2, 8192, 16383);
            final Oid b = new Oid(1, 2, 8192, 16383, 1);
            assertNotEquals(a, b);
        }
        {
            final Oid a = new Oid();
            final Oid b = new Oid(1, 2, 8192, 16383, 1);
            assertNotEquals(a, b);
        }
        {
            final Oid a = new Oid();
            assertNotEquals(a, null);
        }
        {
            final Oid a = new Oid();
            assertNotEquals(a, "other type");
        }
    }

    @Test
    public void hashcode() {
        {
            final Oid a = new Oid(1, 2, 8192, 16383);
            final Oid b = new Oid(1, 2, 8192, 16383);
            assertEquals(a.hashCode(), b.hashCode());
        }
        {
            final Oid a = new Oid(1, 2, 8192, 16383);
            final Oid b = new Oid(1, 2, 8192, 16383, 1);
            assertNotEquals(a.hashCode(), b.hashCode());
        }
        {
            final Oid a = new Oid();
            final Oid b = new Oid(1, 2, 8192, 16383, 1);
            assertNotEquals(a.hashCode(), b.hashCode());
        }
    }


    @Test
    public void fromString() throws IOException {
        final Oid expected = new Oid(1, 2, 840, 113549, 1, 1, 1);
        final Oid actual = Oid.fromString("1.2.840.113549.1.1.1");
        assertEquals(expected, actual);
    }


    @Test
    public void fromHex() throws IOException {
        final Oid expected = new Oid(1, 2, 8192, 16383);
        final Oid actual = Oid.fromHex("2ac000ff7f");
        assertEquals(expected, actual);
    }

    @Test
    public void fromBytes() throws IOException {
        //1.2.840.113549.1.1.1
        final Oid oid = Oid.fromBytes(new byte[]{42, -122, 72, -122, -9, 13, 1, 1, 1});

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
