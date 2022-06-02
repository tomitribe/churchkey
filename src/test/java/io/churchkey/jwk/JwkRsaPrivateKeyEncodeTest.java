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
package io.churchkey.jwk;

import io.churchkey.Decoder;
import io.churchkey.JsonAsserts;
import io.churchkey.Key;
import org.junit.Test;
import io.churchkey.Resource;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class JwkRsaPrivateKeyEncodeTest {

    @Test
    public void testKeysDecode1024() throws Exception {
        final Decoder decoder = Key::decode;
        final Resource resource = Resource.resource("rsa", 1024, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final Key key = decoder.decode(resource.bytes("private.jwk"));
        assertKey(expected, key);

        final byte[] encode = Key.encode(key);

        JsonAsserts.assertJson(new String(resource.bytes("private.jwk")), new String(encode));
        assertKey(expected, Key.decode(encode));
    }

    public void assertKey(final RSAPrivateCrtKey expected, final Key key) {
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());

        final RSAPrivateCrtKey actual = (RSAPrivateCrtKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getModulus(), actual.getModulus());
        assertEquals(expected.getPrivateExponent(), actual.getPrivateExponent());
        assertEquals(expected.getPrimeP(), actual.getPrimeP());
        assertEquals(expected.getPrimeQ(), actual.getPrimeQ());
        assertEquals(expected.getPrimeExponentP(), actual.getPrimeExponentP());
        assertEquals(expected.getPrimeExponentQ(), actual.getPrimeExponentQ());
        assertEquals(expected.getCrtCoefficient(), actual.getCrtCoefficient());
    }

    @Test
    public void testKeysDecode2048() throws Exception {
        final Decoder decoder = Key::decode;
        final Resource resource = Resource.resource("rsa", 2048, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final Key key = decoder.decode(resource.bytes("private.jwk"));
        assertKey(expected, key);

        final byte[] encode = Key.encode(key);

        JsonAsserts.assertJson(new String(resource.bytes("private.jwk")), new String(encode));

        assertKey(expected, Key.decode(encode));
    }

}