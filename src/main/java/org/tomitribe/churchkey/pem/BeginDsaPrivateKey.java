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

import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.asn1.Asn1Object;
import org.tomitribe.churchkey.asn1.DerParser;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

public class BeginDsaPrivateKey {

    public static Key decode(final byte[] bytes) {
        try {
            final DerParser parser = new DerParser(bytes);

            final Asn1Object sequence = parser.read();
            if (sequence.getType() != DerParser.SEQUENCE) {
                throw new IllegalArgumentException("Invalid DER: not a sequence");
            }

            // Parse inside the sequence
            final DerParser parser1 = sequence.getParser();

            parser1.read(); // Skip version
            final BigInteger p = parser1.read().getInteger();
            final BigInteger q = parser1.read().getInteger();
            final BigInteger g = parser1.read().getInteger();
            final BigInteger unknown = parser1.read().getInteger();
            final BigInteger x = parser1.read().getInteger();

            final DSAPrivateKeySpec spec = new DSAPrivateKeySpec(x, p, q, g);

            final KeyFactory result = KeyFactory.getInstance("DSA");
            final PrivateKey publicKey = result.generatePrivate(spec);

            return new Key(publicKey, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.PEM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encode(final Key key) {
        return null;
    }

}
