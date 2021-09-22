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
package org.tomitribe.churchkey.ssh;

import org.junit.Ignore;
import org.junit.Test;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;
import org.tomitribe.churchkey.Resource;
import org.tomitribe.churchkey.ec.ECParameterSpecs;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class OpenSSHPublicKeyTest {

    @Test
    public void testRSADecode1024() throws Exception {
        assertDecodeRsaPublicKey(1024, 256);
    }

    @Test
    public void testRSADecode2048() throws Exception {
        assertDecodeRsaPublicKey(2048, 256);
    }

    private void assertDecodeRsaPublicKey(final int rsaBits, final int shaBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource("rsa", rsaBits, shaBits);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPublicKey expected = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.openssh"));
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());

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
            assertEquals(new String(resource.bytes("public.openssh")), exported);
        }

    }

    @Test
    public void testDSADecode1024() throws Exception {
        assertDecodeDsaPublicKey(1024, 256);
    }


    @Test
    @Ignore
    public void testECDecode() throws Exception {
        final Resource resource = Resource.resource("ecdsa-nistp256");

        final Key key = Keys.decode(resource.bytes("public.openssh"));
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());

        final byte[] encoded = Keys.encode(key);
        assertEquals(new String(resource.bytes("public.openssh")), new String(encoded));
    }

    private void assertDecodeDsaPublicKey(final int rsaBits, final int shaBits) throws Exception {
        final Resource resource = Resource.resource("dsa", rsaBits, shaBits);

        final KeyFactory rsa = KeyFactory.getInstance("DSA");
        final DSAPublicKey expected = (DSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.openssh"));
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());

        final DSAPublicKey actual = (DSAPublicKey) key.getKey();

        assertEquals(expected.getY(), actual.getY());
        assertEquals(expected.getParams().getG(), actual.getParams().getG());
        assertEquals(expected.getParams().getQ(), actual.getParams().getQ());
        assertEquals(expected.getParams().getP(), actual.getParams().getP());

        { // Export to PEM
            final String exported = new String(key.encode(Key.Format.PEM));
            assertEquals(new String(resource.bytes("public.pkcs8.pem")), exported);
        }
        { // Export to OPENSSH
            // PEM Public Keys do not have comments, so remove the comment from the expected output
            final String exported = new String(key.encode(Key.Format.OPENSSH));
            assertEquals(new String(resource.bytes("public.openssh")), exported);
        }
    }

    private void assertDecodeEcPublicKey(final int rsaBits, final int shaBits) throws Exception {
        final Resource resource = Resource.resource("ec", rsaBits, shaBits);

        final KeyFactory rsa = KeyFactory.getInstance("EC");
        final ECPublicKey expected = (ECPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.openssh"));
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());

        final ECPublicKey actual = (ECPublicKey) key.getKey();

        assertEquals(expected.getW(), actual.getW());
        assertTrue(ECParameterSpecs.equals(expected.getParams(), actual.getParams()));

        { // Export to PEM
            final String exported = new String(key.encode(Key.Format.PEM));
            assertEquals(new String(resource.bytes("public.pkcs8.pem")), exported);
        }
        { // Export to OPENSSH
            // PEM Public Keys do not have comments, so remove the comment from the expected output
            final String exported = new String(key.encode(Key.Format.OPENSSH));
            assertEquals(new String(resource.bytes("public.openssh")), exported);
        }
    }

}