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
import org.tomitribe.churchkey.asn1.Oid;
import org.tomitribe.churchkey.dsa.Dsa;
import org.tomitribe.churchkey.ec.Curve;
import org.tomitribe.churchkey.ec.Ecdsa;
import org.tomitribe.churchkey.ec.UnsupportedCurveException;
import org.tomitribe.churchkey.rsa.Rsa;
import org.tomitribe.churchkey.util.Pem;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;
import static org.tomitribe.churchkey.Key.Algorithm.DSA;
import static org.tomitribe.churchkey.Key.Algorithm.EC;
import static org.tomitribe.churchkey.Key.Algorithm.RSA;
import static org.tomitribe.churchkey.asn1.Asn1Type.INTEGER;
import static org.tomitribe.churchkey.asn1.Asn1Type.OCTET_STRING;
import static org.tomitribe.churchkey.asn1.Asn1Type.SEQUENCE;
import static org.tomitribe.churchkey.asn1.DerWriter.write;

public class BeginPrivateKey {

    private static final Oid rsaKey = Oid.fromString("1.2.840.113549.1.1.1");
    private static final Oid dsaKey = Oid.fromString("1.2.840.10040.4.1");
    private static final Oid ecKey = Oid.fromString("1.2.840.10045.2.1");

    private BeginPrivateKey() {
    }

    public static Key decode(final byte[] bytes) {
        try {

            final Oid keyTypeOid = readKeyType(bytes);

            if (rsaKey.equals(keyTypeOid)) {
                return decodeRsaKey(bytes);
            }

            if (dsaKey.equals(keyTypeOid)) {
                return decodeDsaKey(bytes);
            }

            if (ecKey.equals(keyTypeOid)) {
                return decodeEcKey(bytes);
            }

            throw new UnsupportedOperationException("Unsupported key type oid: " + keyTypeOid);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

    }

    private static Key decodeRsaKey(final byte[] bytes) throws IOException {
        final DerParser d1 = new DerParser(bytes);
        final Asn1Object d1o1 = d1.readObject().assertType(Asn1Type.SEQUENCE);
        {
            final DerParser d2 = new DerParser(d1o1.getValue());
            final Asn1Object d2o1 = d2.readObject().assertType(Asn1Type.INTEGER);
            final Asn1Object d2o2 = d2.readObject().assertType(Asn1Type.SEQUENCE);
            {
                final DerParser d3 = new DerParser(d2o2.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(Asn1Type.OBJECT_IDENTIFIER);
                final Asn1Object d3o2 = d3.readObject().assertType(Asn1Type.NULL);
            }
            final Asn1Object d2o3 = d2.readObject().assertType(OCTET_STRING);
            {
                final DerParser d3 = new DerParser(d2o3.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(Asn1Type.SEQUENCE);
                {
                    final DerParser d4 = new DerParser(d3o1.getValue());
                    final BigInteger version = d4.readBigInteger();
                    final RSAPrivateCrtKey privateKey = Rsa.Private.builder()
                            .modulus(d4.readBigInteger())
                            .publicExponent(d4.readBigInteger())
                            .privateExponent(d4.readBigInteger())
                            .primeP(d4.readBigInteger())
                            .primeQ(d4.readBigInteger())
                            .primeExponentP(d4.readBigInteger())
                            .primeExponentQ(d4.readBigInteger())
                            .crtCoefficient(d4.readBigInteger())
                            .build()
                            .toKey();

                    return new Key(privateKey, Key.Type.PRIVATE, RSA, Key.Format.PEM);
                }
            }
        }
    }

    private static Key decodeDsaKey(final byte[] bytes) throws IOException {
        final Dsa.Private.Builder dsa = Dsa.Private.builder();
        final DerParser d1 = new DerParser(bytes);
        final Asn1Object d1o1 = d1.readObject().assertType(Asn1Type.SEQUENCE);
        {
            final DerParser d2 = new DerParser(d1o1.getValue());
            final Asn1Object d2o1 = d2.readObject().assertType(Asn1Type.INTEGER);
            final Asn1Object d2o2 = d2.readObject().assertType(Asn1Type.SEQUENCE);
            {
                final DerParser d3 = new DerParser(d2o2.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(Asn1Type.OBJECT_IDENTIFIER);
                final Asn1Object d3o2 = d3.readObject().assertType(Asn1Type.SEQUENCE);
                {
                    final DerParser d4 = new DerParser(d3o2.getValue());
                    dsa.p(d4.readBigInteger());
                    dsa.q(d4.readBigInteger());
                    dsa.g(d4.readBigInteger());
                }
            }
            final Asn1Object d2o3 = d2.readObject().assertType(OCTET_STRING);
            {
                final DerParser d3 = new DerParser(d2o3.getValue());
                dsa.x(d3.readBigInteger());

                final DSAPrivateKey privateKey = dsa.build().toKey();
                return new Key(privateKey, Key.Type.PRIVATE, DSA, Key.Format.PEM);
            }
        }
    }

    /**
     * EC Keys start out with this wrapper identifying the curve by OID
     *
     *     0:d=0  hl=2 l= 112 cons: SEQUENCE
     *     2:d=1  hl=2 l=   1 prim:  INTEGER           :00
     *     5:d=1  hl=2 l=  20 cons:  SEQUENCE
     *     7:d=2  hl=2 l=   7 prim:   OBJECT            :id-ecPublicKey
     *    16:d=2  hl=2 l=   9 prim:   OBJECT            :brainpoolP192r1
     *    27:d=1  hl=2 l=  85 prim:  OCTET STRING
     *       0000 - 30 53 02 01 01 04 18 88-9f 26 37 f9 f5 1f da 16   0S.......&7.....
     *       0010 - 1c b0 4c ce 79 09 36 b0-b6 8f 22 80 4d a0 ff a1   ..L.y.6...".M...
     *       0020 - 34 03 32 00 04 46 c1 7d-10 61 08 39 73 14 45 d0   4.2..F.}.a.9s.E.
     *       0030 - 8d 3b ac 12 05 a5 ef 45-d3 fb 33 cf 91 81 e8 43   .;.....E..3....C
     *       0040 - dd ab cb b7 de 04 64 b0-82 a6 59 27 c9 0d b2 25   ......d...Y'...%
     *       0050 - 32 20 c0 d6 38                                    2 ..8
     *
     * The above OCTET STRING at byte 27 (in this example) contains the actual key values
     * and is in the following format once decoded.
     *
     *    0:d=0  hl=2 l=  83 cons: SEQUENCE
     *     2:d=1  hl=2 l=   1 prim:  INTEGER           :01
     *     5:d=1  hl=2 l=  24 prim:  OCTET STRING
     *       0000 - 88 9f 26 37 f9 f5 1f da-16 1c b0 4c ce 79 09 36   ..&7.......L.y.6
     *       0010 - b0 b6 8f 22 80 4d a0 ff-                          ...".M..
     *    31:d=1  hl=2 l=  52 cons:  cont [ 1 ]
     *    33:d=2  hl=2 l=  50 prim:   BIT STRING
     *       0000 - 00 04 46 c1 7d 10 61 08-39 73 14 45 d0 8d 3b ac   ..F.}.a.9s.E..;.
     *       0010 - 12 05 a5 ef 45 d3 fb 33-cf 91 81 e8 43 dd ab cb   ....E..3....C...
     *       0020 - b7 de 04 64 b0 82 a6 59-27 c9 0d b2 25 32 20 c0   ...d...Y'...%2 .
     *       0030 - d6 38                                             .8
     *
     * The above OCTET STRING contains the private key BigInteger.
     * The BIT STRING contains the public key ECPoint (x, y) values.
     */
    private static Key decodeEcKey(final byte[] bytes) throws IOException {
        final Ecdsa.Private.Builder ecdsa = Ecdsa.Private.builder();
        final DerParser d1 = new DerParser(bytes);
        final Asn1Object d1o1 = d1.readObject().assertType(Asn1Type.SEQUENCE);
        {
            final DerParser d2 = new DerParser(d1o1.getValue());
            final Asn1Object d2o1 = d2.readObject().assertType(Asn1Type.INTEGER);
            final Asn1Object d2o2 = d2.readObject().assertType(Asn1Type.SEQUENCE);
            {
                final DerParser d3 = new DerParser(d2o2.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(Asn1Type.OBJECT_IDENTIFIER);
                final Asn1Object d3o2 = d3.readObject();

                if (d3o2.isType(Asn1Type.OBJECT_IDENTIFIER)) {
                    /*
                     * An OID naming a curve is encoded
                     */
                    final Oid oid = d3o2.asOID();
                    final Curve curve = Curve.resolve(oid);
                    if (curve == null) {
                        throw new UnsupportedCurveException(oid.toString());
                    }
                    ecdsa.curve(curve);
                } else if (d3o2.isType(SEQUENCE)) {
                    /*
                     * The actual curve parameters are encoded
                     */
                    final ECParameterSpec parameterSpec = EcCurveParams.parseSequence(d3o2);
                    ecdsa.spec(parameterSpec);
                }
            }
            final Asn1Object d2o3 = d2.readObject().assertType(OCTET_STRING);
            {
                final DerParser d3 = new DerParser(d2o3.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(SEQUENCE);
                {
                    final DerParser d4 = new DerParser(d3o1.getValue());
                    final Asn1Object d4o1 = d4.readObject().assertType(INTEGER);
                    final Asn1Object d4o2 = d4.readObject().assertType(OCTET_STRING);

                    ecdsa.d(new BigInteger(d4o2.getValue()));

                    final ECPrivateKey privateKey = ecdsa.build().toKey();
                    return new Key(privateKey, Key.Type.PRIVATE, EC, Key.Format.PEM);
                }
            }
        }
    }

    private static Oid readKeyType(final byte[] bytes) throws IOException {
        final DerParser d1 = new DerParser(bytes);
        final Asn1Object d1o1 = d1.readObject().assertType(Asn1Type.SEQUENCE);
        {
            final DerParser d2 = new DerParser(d1o1.getValue());
            final Asn1Object d2o1 = d2.readObject().assertType(Asn1Type.INTEGER);
            final Asn1Object d2o2 = d2.readObject().assertType(Asn1Type.SEQUENCE);
            {
                final DerParser d3 = new DerParser(d2o2.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(Asn1Type.OBJECT_IDENTIFIER);

                return d3o1.asOID();
            }
        }
    }

    public static byte[] encode(final Key key) {
        final byte[] derEncodedBytes = toDer(key);

        return Pem.builder()
                .type("PRIVATE KEY")
                .data(derEncodedBytes)
                .wrap(64)
                .format()
                .getBytes();
    }

    public static byte[] toDer(final Key key) {
        if (key.getAlgorithm() == RSA) {
            final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key.getKey();
            return encodeRsa(privateKey);
        }

        if (key.getAlgorithm() == DSA) {
            final DSAPrivateKey privateKey = (DSAPrivateKey) key.getKey();
            return encodeDsa(privateKey);
        }

        if (key.getAlgorithm() == EC) {
            final ECPrivateKey privateKey = (ECPrivateKey) key.getKey();
            return encodeEc(privateKey);
        }

        return null;
    }

    private static byte[] encodeDsa(final DSAPrivateKey privateKey) {
        return write()
                .sequence(write()
                        .integer(ZERO)
                        .sequence(write()
                                .objectIdentifier(dsaKey)
                                .sequence(write()
                                        .integer(privateKey.getParams().getP())
                                        .integer(privateKey.getParams().getQ())
                                        .integer(privateKey.getParams().getG())))
                        .octetString(write()
                                .integer(privateKey.getX())))
                .bytes();
    }

    private static byte[] encodeRsa(final RSAPrivateCrtKey privateKey) {
        return write()
                .sequence(write()
                        .integer(ZERO)
                        .sequence(write()
                                .objectIdentifier(rsaKey)
                                .nill())
                        .octetString(write()
                                .sequence(write()
                                        .integer(ZERO)
                                        .integer(privateKey.getModulus())
                                        .integer(privateKey.getPublicExponent())
                                        .integer(privateKey.getPrivateExponent())
                                        .integer(privateKey.getPrimeP())
                                        .integer(privateKey.getPrimeQ())
                                        .integer(privateKey.getPrimeExponentP())
                                        .integer(privateKey.getPrimeExponentQ())
                                        .integer(privateKey.getCrtCoefficient()))))
                .bytes();
    }

    /**
     *     0:d=0  hl=2 l=  84 cons: SEQUENCE
     *     2:d=1  hl=2 l=   1 prim:  INTEGER           :00
     *     5:d=1  hl=2 l=  16 cons:  SEQUENCE
     *     7:d=2  hl=2 l=   7 prim:   OBJECT            :id-ecPublicKey
     *    16:d=2  hl=2 l=   5 prim:   OBJECT            :secp128r1
     *    23:d=1  hl=2 l=  61 prim:  OCTET STRING
     *       0000 - 30 3b 02 01 01 04 10 12-d9 68 7a e0 21 c4 b4 ee   0;.......hz.!...
     *       0010 - cd e2 46 27 e4 55 10 a1-24 03 22 00 04 19 ef 1d   ..F'.U..$.".....
     *       0020 - d1 8e 15 82 f0 fb a9 a8-e7 3f 79 f8 79 d4 ab 9e   .........?y.y...
     *       0030 - 5d 6d 40 33 d8 d0 fe 6d-43 71 fb bc e5            ]m@3...mCq...
     *
     * The OCTET STRING is formatted as follows
     *
     *     0:d=0  hl=2 l=  59 cons: SEQUENCE
     *     2:d=1  hl=2 l=   1 prim:  INTEGER           :01
     *     5:d=1  hl=2 l=  16 prim:  OCTET STRING
     *       0000 - 12 d9 68 7a e0 21 c4 b4-ee cd e2 46 27 e4 55 10   ..hz.!.....F'.U.
     *    23:d=1  hl=2 l=  36 cons:  cont [ 1 ]
     *    25:d=2  hl=2 l=  34 prim:   BIT STRING
     *       0000 - 00 04 19 ef 1d d1 8e 15-82 f0 fb a9 a8 e7 3f 79   ..............?y
     *       0010 - f8 79 d4 ab 9e 5d 6d 40-33 d8 d0 fe 6d 43 71 fb   .y...]m@3...mCq.
     *       0020 - bc e5                                             ..
     */
    private static byte[] encodeEc(final ECPrivateKey privateKey) {
        final ECParameterSpec params = privateKey.getParams();
        final Curve curve = Arrays.stream(Curve.values())
                .filter(c -> c.isEqual(params))
                .findFirst().orElseThrow(() -> new IllegalStateException("Unable to resolve OID for ECParameterSpec"));

        return write()
                .sequence(write()
                        .integer(ZERO)
                        .sequence(write()
                                .objectIdentifier(ecKey)
                                .objectIdentifier(curve.getOid()))
                        .octetString(write()
                                .sequence(write()
                                        .integer(ONE)
                                        .octetString(privateKey.getS())
                                )))
                .bytes();
    }

}
