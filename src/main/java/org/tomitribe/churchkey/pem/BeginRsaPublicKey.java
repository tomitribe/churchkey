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
import org.tomitribe.churchkey.asn1.Asn1Type;
import org.tomitribe.churchkey.asn1.DerParser;
import org.tomitribe.churchkey.rsa.Rsa;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.interfaces.RSAPublicKey;

public class BeginRsaPublicKey {

    private BeginRsaPublicKey() {
    }

    public static Key decode(final byte[] bytes) {
        try {
            final DerParser parser = new DerParser(bytes);

            final Asn1Object sequence = parser.readObject();
            if (sequence.getType() != Asn1Type.SEQUENCE) {
                throw new IllegalArgumentException("Invalid DER: not a sequence");
            }

            // Parse inside the sequence
            final DerParser p = sequence.createParser();

            final RSAPublicKey publicKey = Rsa.Public.builder()
                    .modulus(p.readObject().asInteger())
                    .publicExponent(p.readObject().asInteger())
                    .build()
                    .toKey();

            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.PEM);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] encode(final Key key) {
        return null;
    }

}
