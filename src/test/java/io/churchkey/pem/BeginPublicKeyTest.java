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
import io.churchkey.Keys;
import io.churchkey.Resource;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class BeginPublicKeyTest {

    @Test
    public void testRsaDecode1024() throws Exception {
        assertRsaDecode(new PemParser.PemDecoder()::decode, "rsa", 1024);
    }

    @Test
    public void testRsaDecode2048() throws Exception {
        assertRsaDecode(new PemParser.PemDecoder()::decode, "rsa", 2048);
    }

    @Test
    public void testRsaKeysDecode1024() throws Exception {
        assertRsaDecode(Keys::decode, "rsa", 1024);
    }

    @Test
    public void testRsaKeysDecode2048() throws Exception {
        assertRsaDecode(Keys::decode, "rsa", 2048);
    }

    @Test
    public void testDSADecode1024() throws Exception {
        assertDsaDecode(new PemParser.PemDecoder()::decode, "dsa", 1024);
    }

    @Test
    public void testDSAKeysDecode1024() throws Exception {
        assertDsaDecode(Keys::decode, "dsa", 1024);
    }

    public static void assertRsaDecode(final Decoder decoder, final String algorithm, final int bits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource(algorithm, bits, 256);
        final KeyFactory rsa = KeyFactory.getInstance(algorithm.toUpperCase());
        final RSAPublicKey expected = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = decoder.decode(resource.bytes("public.pkcs8.pem"));
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());

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

    public static void assertDsaDecode(final Decoder decoder, final String algorithm, final int bits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource(algorithm, bits, 256);
        final KeyFactory rsa = KeyFactory.getInstance(algorithm.toUpperCase());
        final DSAPublicKey expected = (DSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = decoder.decode(resource.bytes("public.pkcs8.pem"));
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());

        final DSAPublicKey actual = (DSAPublicKey) key.getKey();

        assertEquals(expected.getY(), actual.getY());
        assertEquals(expected.getParams().getG(), actual.getParams().getG());
        assertEquals(expected.getParams().getP(), actual.getParams().getP());
        assertEquals(expected.getParams().getQ(), actual.getParams().getQ());

        { // Export to PEM
            final String exported = new String(key.encode(Key.Format.PEM));
            assertEquals(new String(resource.bytes("public.pkcs8.pem")), exported);
        }
        { // Export to OPENSSH
            // PEM Public Keys do not have comments, so remove the comment from the expected output
            final String exported = new String(key.encode(Key.Format.OPENSSH));
            assertEquals(new String(resource.bytes("public.openssh")).replace(" dblevins@mingus.lan", ""), exported);
        }

    }

}