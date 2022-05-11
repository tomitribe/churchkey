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
package io.churchkey.asn1;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static io.churchkey.asn1.Asn1Type.BIT_STRING;
import static io.churchkey.asn1.Asn1Type.BOOLEAN;
import static io.churchkey.asn1.Asn1Type.INTEGER;
import static io.churchkey.asn1.Asn1Type.OCTET_STRING;
import static io.churchkey.asn1.Asn1Type.SEQUENCE;
import static io.churchkey.asn1.Asn1Type.SET;

public class TagTest {

    @Test
    public void toDer() {
        assertToDer(1, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, BOOLEAN);
        assertToDer(2, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, INTEGER);
        assertToDer(3, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, BIT_STRING);
        assertToDer(4, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, OCTET_STRING);
        assertToDer(48, Asn1Class.UNIVERSAL, Asn1Construction.CONSTRUCTED, SEQUENCE);
        assertToDer(49, Asn1Class.UNIVERSAL, Asn1Construction.CONSTRUCTED, SET);
        assertToDer(-15, Asn1Class.PRIVATE, Asn1Construction.CONSTRUCTED, SET);
        assertToDer(113, Asn1Class.APPLICATION, Asn1Construction.CONSTRUCTED, SET);
    }

    @Test
    public void fromDer() {
        assertFromDer(1, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, BOOLEAN);
        assertFromDer(2, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, INTEGER);
        assertFromDer(3, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, BIT_STRING);
        assertFromDer(4, Asn1Class.UNIVERSAL, Asn1Construction.PRIMITIVE, OCTET_STRING);
        assertFromDer(48, Asn1Class.UNIVERSAL, Asn1Construction.CONSTRUCTED, SEQUENCE);
        assertFromDer(49, Asn1Class.UNIVERSAL, Asn1Construction.CONSTRUCTED, SET);
        assertFromDer(-15, Asn1Class.PRIVATE, Asn1Construction.CONSTRUCTED, SET);
        assertFromDer(113, Asn1Class.APPLICATION, Asn1Construction.CONSTRUCTED, SET);
    }

    private void assertToDer(final int der, final Asn1Class clazz, final Asn1Construction cons, final Asn1Type type) {
        final Tag tag = new Tag(clazz, cons, type);
        assertEquals(der, tag.toDer());
    }

    private void assertFromDer(final int der, final Asn1Class clazz, final Asn1Construction cons, final Asn1Type type) {
        final Tag tag = Tag.fromDer(der);
        assertEquals(clazz, tag.getClazz());
        assertEquals(cons, tag.getConstruction());
        assertEquals(type, tag.getType());
    }
}
