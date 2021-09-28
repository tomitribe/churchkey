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
package org.tomitribe.churchkey.pem;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.tomitribe.churchkey.Decoder;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;
import org.tomitribe.churchkey.Resource;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(Parameterized.class)
public class BeginRsaPrivateKeyTest {

    @Parameterized.Parameters(name = "{0}")
    public static List<Object[]> params() {
        return Arrays.asList(new Object[][]{
                {1024},
                {2048},
        });
    }

    private final int bits;

    public BeginRsaPrivateKeyTest(final int bits) {
        this.bits = bits;
    }

    /**
     * Decode and compare to the DER file parsed by the JVM
     */
    @Test
    public void decode() throws Exception {
        final Resource resource = Resource.resource("rsa", bits, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final byte[] bytes = resource.bytes("private.pkcs1.pem");
        final Key key = Keys.decode(bytes);

        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Type.PRIVATE, key.getType());

        final RSAPrivateCrtKey actual = (RSAPrivateCrtKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getCrtCoefficient(), actual.getCrtCoefficient());
        assertEquals(expected.getPrimeExponentP(), actual.getPrimeExponentP());
        assertEquals(expected.getPrimeExponentQ(), actual.getPrimeExponentQ());
        assertEquals(expected.getPrimeP(), actual.getPrimeP());
        assertEquals(expected.getPrimeQ(), actual.getPrimeQ());
        assertEquals(expected.getPrivateExponent(), actual.getPrivateExponent());
        assertEquals(expected.getModulus(), actual.getModulus());
    }

    @Test
    public void publicKey() throws Exception {
        final Resource resource = Resource.resource("rsa", bits, 256);
        final byte[] bytes = resource.bytes("private.pkcs1.pem");
        final Key key = Keys.decode(bytes).getPublicKey();

        assertNotNull(key);
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Type.PUBLIC, key.getType());

    }
}