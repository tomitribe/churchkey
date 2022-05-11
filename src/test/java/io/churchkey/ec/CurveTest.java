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

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CurveTest {

    @Test
    public void getEnumName() {
        assertEquals("p256", Curve.getEnumName("P-256"));
    }

    @Test
    public void getAliases() {
        final List<Curve> aliases = Curve.secp256r1.getAliases();
        assertEquals(3, aliases.size());
        assertTrue(aliases.contains(Curve.nistp256));
        assertTrue(aliases.contains(Curve.p256));
        assertTrue(aliases.contains(Curve.prime256v1));
    }

    @Test
    public void isAlias() {
        assertTrue(Curve.nistp256.isAlias());
        assertFalse(Curve.secp256r1.isAlias());
    }

    @Test
    public void isEqual() {
        assertTrue(Curve.secp256r1.isEqual(Curve.secp256r1.getParameterSpec()));
        assertTrue(Curve.secp256r1.isEqual(Curve.nistp256.getParameterSpec()));
        assertFalse(Curve.p256.isEqual(Curve.secp256k1.getParameterSpec()));
    }

    @Test
    public void getName() {
        assertEquals("P-256", Curve.p256.getName());
    }

    @Test
    public void resolve() {
    }

    @Test
    public void testResolve() {
    }
}
