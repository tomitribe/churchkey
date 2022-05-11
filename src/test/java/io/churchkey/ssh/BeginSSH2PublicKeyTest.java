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
package io.churchkey.ssh;

import io.churchkey.Key;
import io.churchkey.Keys;
import io.churchkey.Resource;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class BeginSSH2PublicKeyTest {

    @Test
    public void testRSADecode1024() throws Exception {
        assertRSADecode(1024, 256);
    }

    @Test
    public void testRSADecode2048() throws Exception {
        assertRSADecode(2048, 256);
    }

    private void assertRSADecode(final int rsaBits, final int shaBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource("rsa", rsaBits, shaBits);

        final KeyFactory factory = KeyFactory.getInstance("RSA");
        final RSAPublicKey expected = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.ssh2"));
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());

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
            assertEquals(
                    normalizeOpenSSHComment(resource.bytes("public.openssh")),
                    normalizeOpenSSHComment(exported.getBytes())
            );
        }
    }

    /**
     * Our test SSH2 keys will have a longer comment.  This comment will
     * be in the generated output and is valid.  As our generated test
     * OpenSSH keys have a short comment, we simply need to replace that
     * short comment with the expected longer comment.
     */
    private static String normalizeOpenSSHComment(final byte[] bytes) {
        return new String(bytes)
                .replaceAll("dblevins@mingus.lan$", "0000-bit XXX, converted by dblevins@mingus.lan from OpenSSH")
                .replaceAll("[0-9]{4}-bit [A-Z]+", "0000-bit XXX")
                ;
    }

    @Test
    public void testDSADecode1024() throws Exception {
        assertDSADecode(1024, 256);
    }

    private void assertDSADecode(final int rsaBits, final int shaBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource("dsa", rsaBits, shaBits);

        final KeyFactory factory = KeyFactory.getInstance("DSA");
        final DSAPublicKey expected = (DSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.ssh2"));
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());

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
            assertEquals(
                    normalizeOpenSSHComment(resource.bytes("public.openssh")),
                    normalizeOpenSSHComment(exported.getBytes())
            );
        }
    }
}