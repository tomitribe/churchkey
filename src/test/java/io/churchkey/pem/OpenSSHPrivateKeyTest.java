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

import io.churchkey.Decoder;
import io.churchkey.KeyAsserts;
import org.junit.Test;
import io.churchkey.Key;
import io.churchkey.Keys;
import io.churchkey.Resource;

import java.security.KeyFactory;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class OpenSSHPrivateKeyTest {

    @Test
    public void rsa() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("opensshrsa", 2048, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final byte[] bytes = resource.bytes("private.openssh");
        final Key key = decoder.decode(bytes);
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Type.PRIVATE, key.getType());

        final RSAPrivateCrtKey actual = (RSAPrivateCrtKey) key.getKey();

        KeyAsserts.assertRsaPrivateKey(expected, actual);
    }

    @Test
    public void ec() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("ecdsa-nistp256");

        final Key expectedKey = Keys.decode(resource.bytes("private.pkcs8.pem"));
        final ECPrivateKey expected = (ECPrivateKey) expectedKey.getKey();

        final byte[] bytes = resource.bytes("private.openssh");
        final Key key = decoder.decode(bytes);
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Type.PRIVATE, key.getType());

        final ECPrivateKey actual = (ECPrivateKey) key.getKey();

        KeyAsserts.assertEcPrivateKey(expected, actual);
    }

    @Test
    public void dsa() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("opensshdsa");

        final byte[] bytes = resource.bytes("private.openssh");
        final Key key = decoder.decode(bytes);
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Type.PRIVATE, key.getType());

        final DSAPrivateKey expected = (DSAPrivateKey) key.getKey();

        final byte[] encode = key.encode(Key.Format.OPENSSH);
        final Key key2 = Keys.decode(encode);
        final DSAPrivateKey actual = (DSAPrivateKey) key2.getKey();

        KeyAsserts.assertDsaPrivateKey(expected, actual);
    }

}