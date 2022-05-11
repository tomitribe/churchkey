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
package io.churchkey.pem;

import io.churchkey.asn1.Asn1Type;
import io.churchkey.asn1.Asn1Object;
import io.churchkey.asn1.DerParser;
import io.churchkey.asn1.Oid;
import io.churchkey.ec.EcPoints;

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static java.math.BigInteger.ONE;
import static io.churchkey.asn1.DerWriter.write;

public class EcCurveParams {
    public static final ThreadLocal<String> name = new ThreadLocal<>();

    public static final Oid primeField = new Oid(1, 2, 840, 10045, 1, 1);
    public static final Oid characteristicTwoField = new Oid(1, 2, 840, 10045, 1, 2);
    public static final Oid tpBasis = new Oid(1, 2, 840, 10045, 1, 2, 3, 2);
    public static final Oid ppBasis = new Oid(1, 2, 840, 10045, 1, 2, 3, 3);

    private EcCurveParams() {
    }

    public static Oid parseOid(final byte[] data) throws IOException {
        final DerParser d1 = new DerParser(data);
        final Asn1Object d1o1 = d1.readObject().assertType(Asn1Type.OBJECT_IDENTIFIER);
        return d1o1.asOID();
    }

    public static ECParameterSpec parse(final byte[] data) throws IOException {
        final DerParser d1 = new DerParser(data);
        final Asn1Object d1o1 = d1.readObject().assertType(Asn1Type.SEQUENCE);
        return parseSequence(d1o1);
    }

    public static ECParameterSpec parseSequence(final Asn1Object d1o1) throws IOException {
        final ECField field;
        final EllipticCurve ellipticCurve;

        final DerParser d2 = new DerParser(d1o1.getValue());
        final Asn1Object d2o1 = d2.readObject().assertType(Asn1Type.INTEGER);
        final Asn1Object d2o2 = d2.readObject().assertType(Asn1Type.SEQUENCE);
        {
            final DerParser d3 = new DerParser(d2o2.getValue());
            final Asn1Object d3o1 = d3.readObject().assertType(Asn1Type.OBJECT_IDENTIFIER);
            final Oid oid = d3o1.asOID();

            if (primeField.equals(oid)) {
                final Asn1Object d3o2 = d3.readObject().assertType(Asn1Type.INTEGER);
                field = new ECFieldFp(d3o2.toInteger());
            } else if (characteristicTwoField.equals(oid)) {
                final Asn1Object d3o2 = d3.readObject().assertType(Asn1Type.SEQUENCE);
                {
                    final DerParser d4 = new DerParser(d3o2.getValue());
                    final Asn1Object d4o1 = d4.readObject().assertType(Asn1Type.INTEGER);
                    final Asn1Object d4o2 = d4.readObject().assertType(Asn1Type.OBJECT_IDENTIFIER);

                    final Oid basis = d4o2.asOID();

                    if (ppBasis.equals(basis)) {
                        final Asn1Object d4o3 = d4.readObject().assertType(Asn1Type.SEQUENCE);
                        {
                            final DerParser d5 = new DerParser(d4o3.getValue());
                            final Asn1Object d5o1 = d5.readObject().assertType(Asn1Type.INTEGER);
                            final Asn1Object d5o2 = d5.readObject().assertType(Asn1Type.INTEGER);
                            final Asn1Object d5o3 = d5.readObject().assertType(Asn1Type.INTEGER);
                            field = new ECFieldF2m(d4o1.asInteger().intValue(), new int[]{
                                    d5o3.asInteger().intValue(),
                                    d5o2.asInteger().intValue(),
                                    d5o1.asInteger().intValue()
                            });
                        }
                    } else if (tpBasis.equals(basis)) {
                        final Asn1Object d5o1 = d4.readObject().assertType(Asn1Type.INTEGER);
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

        final Asn1Object d2o3 = d2.readObject().assertType(Asn1Type.SEQUENCE);
        {
            final DerParser d3 = new DerParser(d2o3.getValue());
            final Asn1Object d3o1 = d3.readObject().assertType(Asn1Type.OCTET_STRING);
            final Asn1Object d3o2 = d3.readObject().assertType(Asn1Type.OCTET_STRING);
            final Asn1Object d3o3 = d3.readObject();

            final BigInteger a = d3o1.toInteger();
            final BigInteger b = d3o2.toInteger();

            if (d3o3 == null) {
                ellipticCurve = new EllipticCurve(field, a, b);
            } else {
                ellipticCurve = new EllipticCurve(field, a, b, d3o3.getPureValueBytes());
            }
        }

        final Asn1Object d2o4 = d2.readObject().assertType(Asn1Type.OCTET_STRING);
        final Asn1Object d2o5 = d2.readObject().assertType(Asn1Type.INTEGER);
        final Asn1Object d2o6 = d2.readObject().assertType(Asn1Type.INTEGER);

        final ECPoint point = EcPoints.fromBytes(d2o4.getPureValueBytes());
        return new ECParameterSpec(ellipticCurve, point, d2o5.toInteger(), d2o6.toInteger().intValue());
    }

    public static byte[] encode(final ECParameterSpec spec) {
        final EllipticCurve curve = spec.getCurve();
        final ECField field = curve.getField();

        if (field instanceof ECFieldFp) {
            return curve.getSeed() == null ? prime(spec) : primeWithSeed(spec);
        }

        if (field instanceof ECFieldF2m) {
            return binary(spec);
        }

        throw new UnsupportedOperationException("Unsupported ECField type: " + field.getClass().getName());
    }

    private static byte[] binary(final ECParameterSpec spec) {
        final ECFieldF2m field = (ECFieldF2m) spec.getCurve().getField();
        final byte[] seed = spec.getCurve().getSeed();

        final int[] terms = field.getMidTermsOfReductionPolynomial();

        if (terms.length == 1) {
            return seed == null ? tpBasis(spec) : tpBasisWithSeed(spec);
        }

        if (terms.length == 3) {
            return seed == null ? ppBasis(spec) : ppBasisWithSeed(spec);
        }

        throw new UnsupportedOperationException("Unsupported number of binary terms " + terms.length);
    }

    /*
     *     0:d=0  hl=3 l= 143 cons: SEQUENCE
     *     3:d=1  hl=2 l=   1 prim:  INTEGER           :01
     *     6:d=1  hl=2 l=  28 cons:  SEQUENCE
     *     8:d=2  hl=2 l=   7 prim:   OBJECT            :characteristic-two-field
     *    17:d=2  hl=2 l=  17 cons:   SEQUENCE
     *    19:d=3  hl=2 l=   1 prim:    INTEGER           :71
     *    22:d=3  hl=2 l=   9 prim:    OBJECT            :tpBasis
     *    33:d=3  hl=2 l=   1 prim:    INTEGER           :09
     *    36:d=1  hl=2 l=  55 cons:  SEQUENCE
     *    38:d=2  hl=2 l=  14 prim:   OCTET STRING
     *       0000 - 68 99 18 db ec 7e 5a 0d-d6 df c0 aa 55 c7         h....~Z.....U.
     *    54:d=2  hl=2 l=  14 prim:   OCTET STRING
     *       0000 - 95 e9 a9 ec 9b 29 7b d4-bf 36 e0 59 18 4f         .....){..6.Y.O
     *    70:d=2  hl=2 l=  21 prim:   BIT STRING
     *       0000 - 00 10 c0 fb 15 76 08 60-de f1 ee f4 d6 96 e6 76   .....v.`.......v
     *       0010 - 87 56 15 17 5d                                    .V..]
     *    93:d=1  hl=2 l=  31 prim:  OCTET STRING
     *       0000 - 04 01 a5 7a 6a 7b 26 ca-5e f5 2f cd b8 16 47 97   ...zj{&.^./...G.
     *       0010 - 00 b3 ad c9 4e d1 fe 67-4c 06 e6 95 ba ba 1d      ....N..gL......
     *   126:d=1  hl=2 l=  15 prim:  INTEGER           :010000000000000108789B2496AF93
     *   143:d=1  hl=2 l=   1 prim:  INTEGER           :02
     */
    private static byte[] tpBasisWithSeed(final ECParameterSpec spec) {
        final ECFieldF2m field = (ECFieldF2m) spec.getCurve().getField();
        return write()
                .sequence(write()
                        .integer(ONE)
                        .sequence(write()
                                .objectIdentifier(characteristicTwoField)
                                .sequence(write()
                                        .integer(field.getM())
                                        .objectIdentifier(tpBasis)
                                        .integer(field.getMidTermsOfReductionPolynomial()[0])
                                )
                        )
                        .sequence(write()
                                .octetString(spec.getCurve().getA())
                                .octetString(spec.getCurve().getB())
                                .bitString(spec.getCurve().getSeed())
                        )
                        .octetString(EcPoints.toBytes(spec.getGenerator()))
                        .integer(spec.getOrder())
                        .integer(spec.getCofactor())
                )
                .bytes();
    }

    private static byte[] tpBasis(final ECParameterSpec spec) {
        final ECFieldF2m field = (ECFieldF2m) spec.getCurve().getField();
        return write()
                .sequence(write()
                        .integer(ONE)
                        .sequence(write()
                                .objectIdentifier(characteristicTwoField)
                                .sequence(write()
                                        .integer(field.getM())
                                        .objectIdentifier(tpBasis)
                                        .integer(field.getMidTermsOfReductionPolynomial()[0])
                                )
                        )
                        .sequence(write()
                                .octetString(spec.getCurve().getA())
                                .octetString(spec.getCurve().getB())
                        )
                        .octetString(EcPoints.toBytes(spec.getGenerator()))
                        .integer(spec.getOrder())
                        .integer(spec.getCofactor())
                )
                .bytes();
    }

    /*
     *     0:d=0  hl=3 l= 164 cons: SEQUENCE
     *     3:d=1  hl=2 l=   1 prim:  INTEGER           :01
     *     6:d=1  hl=2 l=  37 cons:  SEQUENCE
     *     8:d=2  hl=2 l=   7 prim:   OBJECT            :characteristic-two-field
     *    17:d=2  hl=2 l=  26 cons:   SEQUENCE
     *    19:d=3  hl=2 l=   2 prim:    INTEGER           :83
     *    23:d=3  hl=2 l=   9 prim:    OBJECT            :ppBasis
     *    34:d=3  hl=2 l=   9 cons:    SEQUENCE
     *    36:d=4  hl=2 l=   1 prim:     INTEGER           :02
     *    39:d=4  hl=2 l=   1 prim:     INTEGER           :03
     *    42:d=4  hl=2 l=   1 prim:     INTEGER           :08
     *    45:d=1  hl=2 l=  61 cons:  SEQUENCE
     *    47:d=2  hl=2 l=  17 prim:   OCTET STRING
     *       0000 - 07 a1 1b 09 a7 6b 56 21-44 41 8f f3 ff 8c 25 70   .....kV!DA....%p
     *       0010 - b8                                                .
     *    66:d=2  hl=2 l=  17 prim:   OCTET STRING
     *       0000 - 02 17 c0 56 10 88 4b 63-b9 c6 c7 29 16 78 f9 d3   ...V..Kc...).x..
     *       0010 - 41                                                A
     *    85:d=2  hl=2 l=  21 prim:   BIT STRING
     *       0000 - 00 4d 69 6e 67 68 75 61-51 75 98 5b d3 ad ba da   .MinghuaQu.[....
     *       0010 - 21 b4 3a 97 e2                                    !.:..
     *   108:d=1  hl=2 l=  35 prim:  OCTET STRING
     *       0000 - 04 00 81 ba f9 1f df 98-33 c4 0f 9c 18 13 43 63   ........3.....Cc
     *       0010 - 83 99 07 8c 6e 7e a3 8c-00 1f 73 c8 13 4b 1b 4e   ....n~....s..K.N
     *       0020 - f9 e1 50                                          ..P
     *   145:d=1  hl=2 l=  17 prim:  INTEGER           :0400000000000000023123953A9464B54D
     *   164:d=1  hl=2 l=   1 prim:  INTEGER           :02
     */
    private static byte[] ppBasisWithSeed(final ECParameterSpec spec) {
        final ECFieldF2m field = (ECFieldF2m) spec.getCurve().getField();
        final int[] terms = field.getMidTermsOfReductionPolynomial();
        return write()
                .sequence(write()
                        .integer(ONE)
                        .sequence(write()
                                .objectIdentifier(characteristicTwoField)
                                .sequence(write()
                                        .integer(field.getM())
                                        .objectIdentifier(ppBasis)
                                        .sequence(write()
                                                .integer(terms[2])
                                                .integer(terms[1])
                                                .integer(terms[0])
                                        )
                                )
                        )
                        .sequence(write()
                                .octetString(spec.getCurve().getA())
                                .octetString(spec.getCurve().getB())
                                .bitString(spec.getCurve().getSeed())
                        )
                        .octetString(EcPoints.toBytes(spec.getGenerator()))
                        .integer(spec.getOrder())
                        .integer(spec.getCofactor())
                )
                .bytes();
    }

    private static byte[] ppBasis(final ECParameterSpec spec) {
        final ECFieldF2m field = (ECFieldF2m) spec.getCurve().getField();
        final int[] terms = field.getMidTermsOfReductionPolynomial();
        return write()
                .sequence(write()
                        .integer(ONE)
                        .sequence(write()
                                .objectIdentifier(characteristicTwoField)
                                .sequence(write()
                                        .integer(field.getM())
                                        .objectIdentifier(ppBasis)
                                        .sequence(write()
                                                .integer(terms[2])
                                                .integer(terms[1])
                                                .integer(terms[0])
                                        )
                                )
                        )
                        .sequence(write()
                                .octetString(spec.getCurve().getA())
                                .octetString(spec.getCurve().getB())
                        )
                        .octetString(EcPoints.toBytes(spec.getGenerator()))
                        .integer(spec.getOrder())
                        .integer(spec.getCofactor())
                )
                .bytes();
    }

    /*
     *     0:d=0  hl=3 l= 247 cons: SEQUENCE
     *     3:d=1  hl=2 l=   1 prim:  INTEGER           :01
     *     6:d=1  hl=2 l=  44 cons:  SEQUENCE
     *     8:d=2  hl=2 l=   7 prim:   OBJECT            :prime-field
     *    17:d=2  hl=2 l=  33 prim:   INTEGER           :FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
     *    52:d=1  hl=2 l=  91 cons:  SEQUENCE
     *    54:d=2  hl=2 l=  32 prim:   OCTET STRING
     *       0000 - ff ff ff ff 00 00 00 01-00 00 00 00 00 00 00 00   ................
     *       0010 - 00 00 00 00 ff ff ff ff-ff ff ff ff ff ff ff fc   ................
     *    88:d=2  hl=2 l=  32 prim:   OCTET STRING
     *       0000 - 5a c6 35 d8 aa 3a 93 e7-b3 eb bd 55 76 98 86 bc   Z.5..:.....Uv...
     *       0010 - 65 1d 06 b0 cc 53 b0 f6-3b ce 3c 3e 27 d2 60 4b   e....S..;.<>'.`K
     *   122:d=2  hl=2 l=  21 prim:   BIT STRING
     *       0000 - 00 c4 9d 36 08 86 e7 04-93 6a 66 78 e1 13 9d 26   ...6.....jfx...&
     *       0010 - b7 81 9f 7e 90                                    ...~.
     *   145:d=1  hl=2 l=  65 prim:  OCTET STRING
     *       0000 - 04 6b 17 d1 f2 e1 2c 42-47 f8 bc e6 e5 63 a4 40   .k....,BG....c.@
     *       0010 - f2 77 03 7d 81 2d eb 33-a0 f4 a1 39 45 d8 98 c2   .w.}.-.3...9E...
     *       0020 - 96 4f e3 42 e2 fe 1a 7f-9b 8e e7 eb 4a 7c 0f 9e   .O.B........J|..
     *       0030 - 16 2b ce 33 57 6b 31 5e-ce cb b6 40 68 37 bf 51   .+.3Wk1^...@h7.Q
     *       0040 - f5                                                .
     *   212:d=1  hl=2 l=  33 prim:  INTEGER           :FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
     *   247:d=1  hl=2 l=   1 prim:  INTEGER           :01
     */
    private static byte[] primeWithSeed(final ECParameterSpec spec) {
        final ECFieldFp field = (ECFieldFp) spec.getCurve().getField();
        return write()
                .sequence(write()
                        .integer(ONE)
                        .sequence(write()
                                .objectIdentifier(primeField)
                                .integer(field.getP())
                        )
                        .sequence(write()
                                .octetString(spec.getCurve().getA())
                                .octetString(spec.getCurve().getB())
                                .bitString(spec.getCurve().getSeed())
                        )
                        .octetString(EcPoints.toBytes(spec.getGenerator()))
                        .integer(spec.getOrder())
                        .integer(spec.getCofactor())
                )
                .bytes();
    }

    private static byte[] prime(final ECParameterSpec spec) {
        final ECFieldFp field = (ECFieldFp) spec.getCurve().getField();
        return write()
                .sequence(write()
                        .integer(ONE)
                        .sequence(write()
                                .objectIdentifier(primeField)
                                .integer(field.getP())
                        )
                        .sequence(write()
                                .octetString(spec.getCurve().getA())
                                .octetString(spec.getCurve().getB())
                        )
                        .octetString(EcPoints.toBytes(spec.getGenerator()))
                        .integer(spec.getOrder())
                        .integer(spec.getCofactor())
                )
                .bytes();
    }


}
