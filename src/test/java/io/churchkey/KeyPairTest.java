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
package io.churchkey;

import org.junit.Assert;
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
        final Key expected = generate(Key.Algorithm.RSA);

        final byte[] encoded = expected.encode(format);

        final Key actual = Keys.decode(encoded);

        Assert.assertEquals(Key.Type.PRIVATE, actual.getType());
        assertEquals(format, actual.getFormat());
        Assert.assertEquals(Key.Algorithm.RSA, actual.getAlgorithm());

        assertNotNull(actual.getPublicKey());
        Assert.assertEquals(Key.Type.PUBLIC, actual.getPublicKey().getType());
        assertEquals(format, actual.getPublicKey().getFormat());
        Assert.assertEquals(Key.Algorithm.RSA, actual.getPublicKey().getAlgorithm());

        KeyAsserts.assertRsaPrivateKey((RSAPrivateCrtKey) expected.getKey(), (RSAPrivateCrtKey) actual.getKey());
        KeyAsserts.assertRsaPublicKey((RSAPublicKey) expected.getPublicKey().getKey(), (RSAPublicKey) actual.getPublicKey().getKey());
    }

    @Test
    @Skip({"SSH2"})
    public void dsa() throws Exception {
        final Key expected = generate(Key.Algorithm.DSA);

        final byte[] encoded = expected.encode(format);

        final Key actual = Keys.decode(encoded);

        Assert.assertEquals(Key.Type.PRIVATE, actual.getType());
        assertEquals(format, actual.getFormat());
        Assert.assertEquals(Key.Algorithm.DSA, actual.getAlgorithm());

        assertNotNull(actual.getPublicKey());
        Assert.assertEquals(Key.Type.PUBLIC, actual.getPublicKey().getType());
        assertEquals(format, actual.getPublicKey().getFormat());
        Assert.assertEquals(Key.Algorithm.DSA, actual.getPublicKey().getAlgorithm());

        KeyAsserts.assertDsaPrivateKey((DSAPrivateKey) expected.getKey(), (DSAPrivateKey) actual.getKey());
        KeyAsserts.assertDsaPublicKey((DSAPublicKey) expected.getPublicKey().getKey(), (DSAPublicKey) actual.getPublicKey().getKey());
    }

    @Test
    @Skip({"SSH2"})
    public void ec() throws Exception {
        final Key expected = generate(Key.Algorithm.EC);

        final byte[] encoded = expected.encode(format);

        final Key actual = Keys.decode(encoded);

        Assert.assertEquals(Key.Type.PRIVATE, actual.getType());
        assertEquals(format, actual.getFormat());
        Assert.assertEquals(Key.Algorithm.EC, actual.getAlgorithm());

        assertNotNull(actual.getPublicKey());
        Assert.assertEquals(Key.Type.PUBLIC, actual.getPublicKey().getType());
        assertEquals(format, actual.getPublicKey().getFormat());
        Assert.assertEquals(Key.Algorithm.EC, actual.getPublicKey().getAlgorithm());

        KeyAsserts.assertEcPrivateKey((ECPrivateKey) expected.getKey(), (ECPrivateKey) actual.getKey());
        KeyAsserts.assertEcPublicKey((ECPublicKey) expected.getPublicKey().getKey(), (ECPublicKey) actual.getPublicKey().getKey());
    }

    private Key generate(final Key.Algorithm algorithm) throws NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.name());
        final KeyPair pair = generator.generateKeyPair();
        return Keys.of(pair);
    }
}
