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
import org.tomitribe.churchkey.dsa.Dsa;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.interfaces.DSAPrivateKey;

public class BeginDsaPrivateKey {

    private BeginDsaPrivateKey() {
    }

    public static Key decode(final byte[] bytes) {
        try {
            final DerParser parser = new DerParser(bytes);

            final Asn1Object sequence = parser.readObject();
            if (sequence.getType() != Asn1Type.SEQUENCE) {
                throw new IllegalArgumentException("Invalid DER: not a sequence");
            }

            // Parse inside the sequence
            final DerParser parser1 = sequence.createParser();

            parser1.readObject(); // Skip version
            final DSAPrivateKey privateKey = Dsa.Private.builder()
                    .p(parser1.readObject().asInteger())
                    .q(parser1.readObject().asInteger())
                    .g(parser1.readObject().asInteger())
                    .y(parser1.readObject().asInteger())
                    .x(parser1.readObject().asInteger())
                    .build()
                    .toKey();

            return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.PEM);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public static byte[] encode(final Key key) {
        return null;
    }

}
