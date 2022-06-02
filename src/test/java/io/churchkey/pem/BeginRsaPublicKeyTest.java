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
package io.churchkey.pem;

import org.junit.Test;
import io.churchkey.Decoder;
import io.churchkey.JsonAsserts;
import io.churchkey.Key;
import io.churchkey.Resource;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class BeginRsaPublicKeyTest {

    @Test
    public void testDecode1024() throws Exception {
        final Decoder decoder = new PemParser.PemDecoder()::decode;
        final Resource resource = Resource.resource("rsa", 1024, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void testDecode2048() throws Exception {
        final Decoder decoder = new PemParser.PemDecoder()::decode;
        final Resource resource = Resource.resource("rsa", 2048, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void testKeysDecode1024() throws Exception {
        final Decoder decoder = Key::decode;
        final Resource resource = Resource.resource("rsa", 1024, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void testKeysDecode2048() throws Exception {
        final Decoder decoder = Key::decode;
        final Resource resource = Resource.resource("rsa", 2048, 256);

        assertDecode(decoder, resource);
    }

    public static void assertDecode(final Decoder decoder, final Resource resource) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPublicKey expected = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = decoder.decode(resource.bytes("public.pkcs1.pem"));
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());

        final RSAPublicKey actual = (RSAPublicKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getModulus(), actual.getModulus());

        { // Export to PEM
            final String exported = new String(key.encode(Key.Format.PEM));
            assertEquals(new String(resource.bytes("public.pkcs8.pem")), exported);
        }
        { // Export to OPENSSH
            // PEM Public Keys do not have comments, so remove the comment from the expected output
            final String exported = new String(key.encode(Key.Format.OPENSSH));
            assertEquals(new String(resource.bytes("public.openssh")).replace(" dblevins@mingus.lan", ""), exported);
        }
        { // Export to JWK
            final String exported = new String(key.encode(Key.Format.JWK));
            JsonAsserts.assertJson(new String(resource.bytes("public.jwk")), exported);
        }
    }
}