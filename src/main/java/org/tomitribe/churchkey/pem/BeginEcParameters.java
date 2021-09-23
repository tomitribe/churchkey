/*
 * Copyright 2021 Tomitribe and community
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.tomitribe.churchkey.pem;

import org.tomitribe.churchkey.asn1.Asn1Type;
import org.tomitribe.churchkey.asn1.DerParser;
import org.tomitribe.churchkey.asn1.Oid;
import org.tomitribe.churchkey.util.Pem;
import org.tomitribe.churchkey.util.Utils;

import java.io.IOException;
import java.security.spec.ECParameterSpec;

/**
 * Parses PEM files that start with "BEGIN EC PARAMETERS"
 */
public class BeginEcParameters {
    private BeginEcParameters() {
    }

    public static byte[] encode(final ECParameterSpec params) {
        return null;
    }

    public static byte[] encode(final Oid oid) {
        return null;
    }

    public static Object decode(final byte[] bytes) throws IOException {
        if (!Utils.startsWith("-----BEGIN EC PARAMETERS-----", bytes)) {
            throw new IllegalArgumentException("Contents do not start with -----BEGIN EC PARAMETERS-----");
        }

        final Pem pem = Pem.parse(bytes);
        final byte[] data = pem.getData();
        final Asn1Type type = new DerParser(data).readObject().getType();

        if (type == Asn1Type.SEQUENCE) {
            return EcCurveParams.parse(data);
        }
        
        if (type == Asn1Type.OBJECT_IDENTIFIER) {
            return EcCurveParams.parseOid(data);
        }
        
        throw new UnsupportedOperationException("Unexpected ASN1 type: " + type);
    }

}
