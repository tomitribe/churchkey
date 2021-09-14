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

import org.tomitribe.churchkey.asn1.Asn1Object;
import org.tomitribe.churchkey.asn1.DerParser;
import org.tomitribe.churchkey.asn1.Oid;
import org.tomitribe.churchkey.ssh.OpenSSHPrivateKey;

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static org.tomitribe.churchkey.asn1.Asn1Type.INTEGER;
import static org.tomitribe.churchkey.asn1.Asn1Type.OBJECT_IDENTIFIER;
import static org.tomitribe.churchkey.asn1.Asn1Type.OCTET_STRING;
import static org.tomitribe.churchkey.asn1.Asn1Type.SEQUENCE;

public class EcCurveParams {
    private static final Oid primeField = new Oid(1, 2, 840, 10045, 1, 1);
    private static final Oid characteristicTwoField = new Oid(1, 2, 840, 10045, 1, 2);
    private static final Oid tpBasis = new Oid(1, 2, 840, 10045, 1, 2, 3, 2);
    private static final Oid ppBasis = new Oid(1, 2, 840, 10045, 1, 2, 3, 3);

    private EcCurveParams() {
    }

    public static ECParameterSpec parse(final byte[] data) throws IOException {
        final DerParser d1 = new DerParser(data);
        final Asn1Object d1o1 = d1.readObject().assertType(SEQUENCE);
        {
            final ECField field;
            final EllipticCurve ellipticCurve;

            final DerParser d2 = new DerParser(d1o1.getValue());
            final Asn1Object d2o1 = d2.readObject().assertType(INTEGER);
            final Asn1Object d2o2 = d2.readObject().assertType(SEQUENCE);
            {
                final DerParser d3 = new DerParser(d2o2.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(OBJECT_IDENTIFIER);
                final Oid oid = d3o1.asOID();

                if (primeField.equals(oid)) {
                    final Asn1Object d3o2 = d3.readObject().assertType(INTEGER);
                    field = new ECFieldFp(d3o2.toInteger());
                } else if (characteristicTwoField.equals(oid)) {
                    final Asn1Object d3o2 = d3.readObject().assertType(SEQUENCE);
                    {
                        final DerParser d4 = new DerParser(d3o2.getValue());
                        final Asn1Object d4o1 = d4.readObject().assertType(INTEGER);
                        final Asn1Object d4o2 = d4.readObject().assertType(OBJECT_IDENTIFIER);

                        final Oid basis = d4o2.asOID();

                        if (ppBasis.equals(basis)) {
                            final Asn1Object d4o3 = d4.readObject().assertType(SEQUENCE);
                            {
                                final DerParser d5 = new DerParser(d4o3.getValue());
                                final Asn1Object d5o1 = d5.readObject().assertType(INTEGER);
                                final Asn1Object d5o2 = d5.readObject().assertType(INTEGER);
                                final Asn1Object d5o3 = d5.readObject().assertType(INTEGER);
                                field = new ECFieldF2m(d4o1.asInteger().intValue(), new int[]{
                                        d5o3.asInteger().intValue(),
                                        d5o2.asInteger().intValue(),
                                        d5o1.asInteger().intValue()
                                });
                            }
                        } else if (tpBasis.equals(basis)) {
                            final Asn1Object d5o1 = d4.readObject().assertType(INTEGER);
                            field = new ECFieldF2m(d4o1.asInteger().intValue(), new int[]{
                                    d5o1.asInteger().intValue()
                            });
                        } else {
                            throw new UnsupportedOperationException("Unsupported characteristic-two-basis " + basis);
                        }
                    }
                } else {
                    throw new UnsupportedOperationException(oid.toString());
                }
            }

            final Asn1Object d2o3 = d2.readObject().assertType(SEQUENCE);
            {
                final DerParser d3 = new DerParser(d2o3.getValue());
                final Asn1Object d3o1 = d3.readObject().assertType(OCTET_STRING);
                final Asn1Object d3o2 = d3.readObject().assertType(OCTET_STRING);
                final Asn1Object d3o3 = d3.readObject();

                final BigInteger a = d3o1.toInteger();
                final BigInteger b = d3o2.toInteger();

                if (d3o3 == null) {
                    ellipticCurve = new EllipticCurve(field, a, b);
                } else {
                    ellipticCurve = new EllipticCurve(field, a, b, d3o3.getPureValueBytes());
                }
            }

            final Asn1Object d2o4 = d2.readObject().assertType(OCTET_STRING);
            final Asn1Object d2o5 = d2.readObject().assertType(INTEGER);
            final Asn1Object d2o6 = d2.readObject().assertType(INTEGER);

            final ECPoint point = OpenSSHPrivateKey.getEcPoint(d2o4.getPureValueBytes());
            return new ECParameterSpec(ellipticCurve, point, d2o5.toInteger(), d2o6.toInteger().intValue());
        }
    }
}
