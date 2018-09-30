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
import org.tomitribe.churchkey.Decoder;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;
import org.tomitribe.churchkey.PemParser;
import org.tomitribe.churchkey.Resource;

import java.security.KeyFactory;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class BeginDsaPrivateKeyTest {

    @Test
    public void testDecode1024() throws Exception {
        final Decoder decoder = new PemParser.PemDecoder()::decode;
        final Resource resource = Resource.resource("dsa", 1024, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void testKeysDecode1024() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("dsa", 1024, 256);

        assertDecode(decoder, resource);
    }

    public void assertDecode(final Decoder decoder, final Resource resource) throws Exception {
        final KeyFactory dsa = KeyFactory.getInstance("DSA");
        final DSAPrivateKey expected = (DSAPrivateKey) dsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final byte[] bytes = resource.bytes("private.pkcs1.pem");
        final Key key = decoder.decode(bytes);
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());

        final DSAPrivateKey actual = (DSAPrivateKey) key.getKey();

        assertEquals(expected.getParams().getG(), actual.getParams().getG());
        assertEquals(expected.getParams().getQ(), actual.getParams().getQ());
        assertEquals(expected.getParams().getP(), actual.getParams().getP());
        assertEquals(expected.getX(), actual.getX());
    }
}