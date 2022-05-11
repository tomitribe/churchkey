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
package io.churchkey.ec;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ECParameterSpecsTest {

    @Test
    public void testEquals() {
        assertTrue(ECParameterSpecs.equals(Curve.nistp256.getParameterSpec(), Curve.secp256r1.getParameterSpec()));
        assertFalse(ECParameterSpecs.equals(Curve.nistp256.getParameterSpec(), Curve.secp256k1.getParameterSpec()));
    }

    @Test
    public void testToString() {
        assertEquals("prime(\n" +
                "    \"00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF\",\n" +
                "    \"00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC\",\n" +
                "    \"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B\",\n" +
                "    \"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296\",\n" +
                "    \"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5\",\n" +
                "    \"00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551\",\n" +
                "    1), null)\n", ECParameterSpecs.toString(Curve.nistp256.getParameterSpec()));

        assertEquals("binary(239, new int[]{36},\n" +
                "    \"32010857077C5431123A46B808906756F543423E8D27877578125778AC76\",\n" +
                "    \"790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16\",\n" +
                "    \"57927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D\",\n" +
                "    \"61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305\",\n" +
                "    \"2000000000000000000000000000000F4D42FFE1492A4993F1CAD666E447\",\n" +
                "    4), null)\n", ECParameterSpecs.toString(Curve.c2tnb239v1.getParameterSpec()));
    }
}
