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
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class BeginRsaPublicKey {

    public static Key decode(final byte[] bytes) {
        try {
            final DerParser parser = new DerParser(bytes);

            final Asn1Object sequence = parser.read();
            if (sequence.getType() != DerParser.SEQUENCE) {
                throw new IllegalArgumentException("Invalid DER: not a sequence");
            }

            // Parse inside the sequence
            final DerParser p = sequence.getParser();

            final BigInteger modulus = p.read().getInteger();
            final BigInteger publicExponent = p.read().getInteger();

            final RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
            final KeyFactory result = KeyFactory.getInstance("RSA");
            final PublicKey publicKey = result.generatePublic(keySpec);

            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.PEM);
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
