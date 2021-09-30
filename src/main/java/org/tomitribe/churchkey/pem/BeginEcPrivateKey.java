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

import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.asn1.Asn1Object;
import org.tomitribe.churchkey.asn1.DerParser;
import org.tomitribe.churchkey.asn1.Oid;
import org.tomitribe.churchkey.ec.Curve;
import org.tomitribe.churchkey.ec.EcPoints;
import org.tomitribe.churchkey.ec.Ecdsa;
import org.tomitribe.churchkey.util.Bytes;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

import static org.tomitribe.churchkey.Key.Algorithm.EC;
import static org.tomitribe.churchkey.asn1.Asn1Type.ANY;
import static org.tomitribe.churchkey.asn1.Asn1Type.BIT_STRING;
import static org.tomitribe.churchkey.asn1.Asn1Type.BOOLEAN;
import static org.tomitribe.churchkey.asn1.Asn1Type.INTEGER;
import static org.tomitribe.churchkey.asn1.Asn1Type.OBJECT_IDENTIFIER;
import static org.tomitribe.churchkey.asn1.Asn1Type.OCTET_STRING;
import static org.tomitribe.churchkey.asn1.Asn1Type.SEQUENCE;

/*
 * Parses "BEGIN EC PRIVATE KEY" PEM contents
 *
 * The asn1 structure will be either of these two formats
 *
 * Private Key with Curve OID (a reference to a curve name)
 *
 *     0:d=0  hl=2 l=  84 cons: SEQUENCE
 *     2:d=1  hl=2 l=   1 prim:  INTEGER           :01
 *     5:d=1  hl=2 l=  20 prim:  OCTET STRING
 *       0000 - a9 50 ed 50 6b cf de 7b-69 97 4b 1b b6 38 2f 53   .P.Pk..{i.K..8/S
 *       0010 - 63 c8 e2                                          c..
 *       0014 - <SPACES/NULS>
 *    27:d=1  hl=2 l=  11 cons:  cont [ 0 ]
 *    29:d=2  hl=2 l=   9 prim:   OBJECT            :brainpoolP160r1
 *    40:d=1  hl=2 l=  44 cons:  cont [ 1 ]
 *    42:d=2  hl=2 l=  42 prim:   BIT STRING
 *       0000 - 00 04 bd cc ec 4a 6c 23-bb f3 14 68 e0 e4 40 5b   .....Jl#...h..@[
 *       0010 - 7a fb 37 7c df 32 9d 01-7a 91 ac f0 d1 90 85 5d   z.7|.2..z......]
 *       0020 - d1 b7 b9 c9 0c a0 9d 29-fb 43                     .......).C
 *
 * Private Key with Curve Parameters (one of three parameter types)
 *
 *     0:d=0  hl=3 l= 229 cons: SEQUENCE
 *     3:d=1  hl=2 l=   1 prim:  INTEGER           :01
 *     6:d=1  hl=2 l=  20 prim:  OCTET STRING
 *       0000 - 8f 6b c3 4e e5 a0 d2 f3-2a 22 fb e6 2d 73 a7 bb   .k.N....*"..-s..
 *       0010 - 79 54 3c 7b                                       yT<{
 *    28:d=1  hl=3 l= 155 cons:  cont [ 0 ]
 *    31:d=2  hl=3 l= 152 cons:   SEQUENCE
 *    34:d=3  hl=2 l=   1 prim:    INTEGER           :01
 *    37:d=3  hl=2 l=  32 cons:    SEQUENCE
 *    39:d=4  hl=2 l=   7 prim:     OBJECT            :prime-field
 *    48:d=4  hl=2 l=  21 prim:     INTEGER           :E95E4A5F737059DC60DFC7AD95B3D8139515620F
 *    71:d=3  hl=2 l=  44 cons:    SEQUENCE
 *    73:d=4  hl=2 l=  20 prim:     OCTET STRING
 *       0000 - 34 0e 7b e2 a2 80 eb 74-e2 be 61 ba da 74 5d 97   4.{....t..a..t].
 *       0010 - e8 f7 c3                                          ...
 *       0014 - <SPACES/NULS>
 *    95:d=4  hl=2 l=  20 prim:     OCTET STRING
 *       0000 - 1e 58 9a 85 95 42 34 12-13 4f aa 2d bd ec 95 c8   .X...B4..O.-....
 *       0010 - d8 67 5e 58                                       .g^X
 *   117:d=3  hl=2 l=  41 prim:    OCTET STRING
 *       0000 - 04 be d5 af 16 ea 3f 6a-4f 62 93 8c 46 31 eb 5a   ......?jOb..F1.Z
 *       0010 - f7 bd bc db c3 16 67 cb-47 7a 1a 8e c3 38 f9 47   ......g.Gz...8.G
 *       0020 - 41 66 9c 97 63 16 da 63-21                        Af..c..c!
 *   160:d=3  hl=2 l=  21 prim:    INTEGER           :E95E4A5F737059DC60DF5991D45029409E60FC09
 *   183:d=3  hl=2 l=   1 prim:    INTEGER           :01
 *   186:d=1  hl=2 l=  44 cons:  cont [ 1 ]
 *   188:d=2  hl=2 l=  42 prim:   BIT STRING
 *       0000 - 00 04 60 a1 ed 34 ac 0e-92 14 72 d6 0e db 08 33   ..`..4....r....3
 *       0010 - 9d d5 f5 71 92 54 3c 42-d3 b4 8a 72 0b 7e d0 3b   ...q.T<B...r.~.;
 *       0020 - 03 f0 11 56 ff 61 b8 10-54 cd                     ...V.a..T.
 */
public class BeginEcPrivateKey {

    private BeginEcPrivateKey() {
    }

    public static Key decode(final byte[] bytes) {
        try {
            final Ecdsa.Private.Builder ec = Ecdsa.Private.builder();
            final DerParser d1 = new DerParser(bytes);
            final Asn1Object d1o1 = d1.readObject().assertType(SEQUENCE);
            {
                final DerParser d2 = new DerParser(d1o1.getValue());
                final Asn1Object d2o1 = d2.readObject().assertType(INTEGER);
                final Asn1Object d2o2 = d2.readObject().assertType(OCTET_STRING);
                final Asn1Object d2o3 = d2.readObject().assertType(ANY);
                {
                    final DerParser d3 = new DerParser(d2o3.getValue());
                    final Asn1Object d3o1 = d3.readObject();

                    if (d3o1.isType(OBJECT_IDENTIFIER)) {

                        final Oid oid = d3o1.asOID();
                        final Curve curve = Curve.resolve(oid);
                        ec.curve(curve);

                    } else if (d3o1.isType(SEQUENCE)) {

                        ec.spec(EcCurveParams.parseSequence(d3o1));

                    }

                    ec.d(d2o2.toInteger());

                }

                final Asn1Object d2o4 = d2.readObject();
                if (d2o4 != null && d2o4.isType(BOOLEAN)) {
                    final DerParser d3 = new DerParser(d2o4.getValue());
                    final Asn1Object d3o1 = d3.readObject().assertType(BIT_STRING);
                    final byte[] value = Bytes.trim(d3o1.getValue());
                    final ECPoint ecPoint = EcPoints.fromBytes(value);
                    ec.x(ecPoint.getAffineX());
                    ec.y(ecPoint.getAffineY());
                }

                final Ecdsa.Private build = ec.build();
                final ECPrivateKey privateKey = build.toKey();
                final ECPublicKey publicKey = build.getX() != null && build.getY() != null ? build.toPublic().toKey() : null;

                return new Key(privateKey, publicKey, Key.Type.PRIVATE, EC, Key.Format.PEM);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
