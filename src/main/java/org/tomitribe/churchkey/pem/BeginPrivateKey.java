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
import org.tomitribe.churchkey.rsa.Rsa;
import org.tomitribe.churchkey.util.Pem;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import static java.math.BigInteger.ZERO;
import static org.tomitribe.churchkey.Key.Algorithm.RSA;
import static org.tomitribe.churchkey.asn1.Asn1Type.OCTET_STRING;
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

            if (dsaKey.equals(keyTypeOid)) {
                return oldDecode(bytes);
            }

            if (ecKey.equals(keyTypeOid)) {
                return oldDecode(bytes);
            }

            throw new UnsupportedOperationException("Unsupported key type oid: " + keyTypeOid);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
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

                return new Oid(d3o1.asOID());
            }
        }
    }

    public static Key oldDecode(final byte[] bytes) {
        try {
            final KeyFactory factory = KeyFactory.getInstance("DSA");
            final DSAPrivateKey privateKey = (DSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(bytes));
            return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        try {
            final KeyFactory factory = KeyFactory.getInstance("EC");
            final ECPrivateKey privateKey = (ECPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(bytes));
            return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.EC, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        throw new UnsupportedOperationException("Unsupported algorithm or invalid PKCS#8 key spec");
    }

    public static byte[] encode(final Key key) {
        if (key.getAlgorithm() == RSA) {
            final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key.getKey();
            final byte[] encoded = write()
                    .sequence(write()
                            .bigInteger(ZERO)
                            .sequence(write()
                                    .objectIdentifier(Oid.fromString("1.2.840.113549.1.1.1"))
                                    .nill())
                            .octetString(write()
                                    .sequence(write()
                                            .bigInteger(ZERO)
                                            .bigInteger(privateKey.getModulus())
                                            .bigInteger(privateKey.getPublicExponent())
                                            .bigInteger(privateKey.getPrivateExponent())
                                            .bigInteger(privateKey.getPrimeP())
                                            .bigInteger(privateKey.getPrimeQ())
                                            .bigInteger(privateKey.getPrimeExponentP())
                                            .bigInteger(privateKey.getPrimeExponentQ())
                                            .bigInteger(privateKey.getCrtCoefficient()))))
                    .bytes();

            return Pem.builder()
                    .type("PRIVATE KEY")
                    .data(encoded)
                    .wrap(64)
                    .format()
                    .getBytes();
        }

        return null;
    }

}
