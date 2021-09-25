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

        if (key.getAlgorithm() == DSA) {
            final DSAPrivateKey privateKey = (DSAPrivateKey) key.getKey();
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

        return null;
    }

}
