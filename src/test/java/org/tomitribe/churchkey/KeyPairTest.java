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
package org.tomitribe.churchkey;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.tomitribe.churchkey.Key.Algorithm.DSA;
import static org.tomitribe.churchkey.Key.Algorithm.EC;
import static org.tomitribe.churchkey.Key.Algorithm.RSA;
import static org.tomitribe.churchkey.Key.Type.PRIVATE;
import static org.tomitribe.churchkey.Key.Type.PUBLIC;
import static org.tomitribe.churchkey.KeyAsserts.assertDsaPrivateKey;
import static org.tomitribe.churchkey.KeyAsserts.assertDsaPublicKey;
import static org.tomitribe.churchkey.KeyAsserts.assertEcPrivateKey;
import static org.tomitribe.churchkey.KeyAsserts.assertEcPublicKey;
import static org.tomitribe.churchkey.KeyAsserts.assertRsaPrivateKey;
import static org.tomitribe.churchkey.KeyAsserts.assertRsaPublicKey;

@RunWith(Parameterized.class)
public class KeyPairTest {

    @Rule
    public Skip.Rule skip = new Skip.Rule();

    @Parameterized.Parameters(name = "{0}")
    public static List<Object[]> params() {
        final List<Object[]> params = new ArrayList<>();
        for (final Key.Format format : Key.Format.values()) {
            params.add(new Object[]{format});
        }
        return params;
    }

    private final Key.Format format;

    public KeyPairTest(final Key.Format format) {
        this.format = format;
    }

    @Test
    @Skip({"SSH2"})
    public void rsa() throws Exception {
        final Key expected = generate(RSA);

        final byte[] encoded = expected.encode(format);

        final Key actual = Keys.decode(encoded);

        assertEquals(PRIVATE, actual.getType());
        assertEquals(format, actual.getFormat());
        assertEquals(RSA, actual.getAlgorithm());

        assertNotNull(actual.getPublicKey());
        assertEquals(PUBLIC, actual.getPublicKey().getType());
        assertEquals(format, actual.getPublicKey().getFormat());
        assertEquals(RSA, actual.getPublicKey().getAlgorithm());

        assertRsaPrivateKey((RSAPrivateCrtKey) expected.getKey(), (RSAPrivateCrtKey) actual.getKey());
        assertRsaPublicKey((RSAPublicKey) expected.getPublicKey().getKey(), (RSAPublicKey) actual.getPublicKey().getKey());
    }

    @Test
    @Skip({"SSH2"})
    public void dsa() throws Exception {
        final Key expected = generate(DSA);

        final byte[] encoded = expected.encode(format);

        final Key actual = Keys.decode(encoded);

        assertEquals(PRIVATE, actual.getType());
        assertEquals(format, actual.getFormat());
        assertEquals(DSA, actual.getAlgorithm());

        assertNotNull(actual.getPublicKey());
        assertEquals(PUBLIC, actual.getPublicKey().getType());
        assertEquals(format, actual.getPublicKey().getFormat());
        assertEquals(DSA, actual.getPublicKey().getAlgorithm());

        assertDsaPrivateKey((DSAPrivateKey) expected.getKey(), (DSAPrivateKey) actual.getKey());
        assertDsaPublicKey((DSAPublicKey) expected.getPublicKey().getKey(), (DSAPublicKey) actual.getPublicKey().getKey());
    }

    @Test
    @Skip({"PEM", "SSH2", "OPENSSH"})
    public void ec() throws Exception {
        final Key expected = generate(EC);

        final byte[] encoded = expected.encode(format);

        final Key actual = Keys.decode(encoded);

        assertEquals(PRIVATE, actual.getType());
        assertEquals(format, actual.getFormat());
        assertEquals(EC, actual.getAlgorithm());

        assertNotNull(actual.getPublicKey());
        assertEquals(PUBLIC, actual.getPublicKey().getType());
        assertEquals(format, actual.getPublicKey().getFormat());
        assertEquals(EC, actual.getPublicKey().getAlgorithm());

        assertEcPrivateKey((ECPrivateKey) expected.getKey(), (ECPrivateKey) actual.getKey());
        assertEcPublicKey((ECPublicKey) expected.getPublicKey().getKey(), (ECPublicKey) actual.getPublicKey().getKey());
    }

    private Key generate(final Key.Algorithm algorithm) throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.name());
        final KeyPair pair = generator.generateKeyPair();
        return new Key(pair.getPrivate(), pair.getPublic(), Key.Type.PRIVATE, algorithm, format);
    }

}
