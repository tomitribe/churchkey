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

import io.churchkey.asn1.Asn1Class;
import org.junit.Ignore;
import org.junit.Test;
import io.churchkey.Key;
import io.churchkey.Resource;
import io.churchkey.asn1.Asn1Dump;
import io.churchkey.asn1.Asn1Object;
import io.churchkey.asn1.Asn1Type;
import io.churchkey.asn1.DerParser;
import io.churchkey.asn1.DerWriter;
import io.churchkey.asn1.Oid;
import io.churchkey.rsa.Rsa;
import io.churchkey.util.Pem;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;

import static java.math.BigInteger.ZERO;
import static org.junit.Assert.assertEquals;
import static io.churchkey.Key.Algorithm.RSA;
import static io.churchkey.asn1.Asn1Type.OCTET_STRING;

public class FooTest {

    @Ignore
    @Test
    public void test() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            try (DerWriter w = new DerWriter(baos)) {
                w.integer(BigInteger.valueOf(-1));
                w.integer(BigInteger.valueOf(129));
                w.integer(new byte[]{0, 0}, 0, 2);
                w.integer(new byte[]{0, 1}, 0, 2);
            }
        } finally {
            baos.close();
        }
        Asn1Dump.print(baos.toByteArray());
    }

    @Ignore
    @Test
    public void test2() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            try (DerWriter w = new DerWriter(baos)) {

                final DerWriter sequence = new DerWriter();
                sequence.integer(BigInteger.valueOf(-1));
                sequence.integer(BigInteger.valueOf(129));
                sequence.integer(new byte[]{0, 0}, 0, 2);
                sequence.integer(new byte[]{0, 1}, 0, 2);
                sequence.close();
                final byte[] bytes = sequence.bytes();
//                Asn1Dump.print(bytes);
                final Asn1Object sequenceAsn1 = new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.SEQUENCE, false, bytes.length, bytes);
                w.writeObject(sequenceAsn1);
            }
        } finally {
            baos.close();
        }
        Asn1Dump.print(baos.toByteArray());
    }

    @Ignore
    @Test
    public void test3() throws Exception {
        final Resource resource = Resource.resource(BeginPrivateKeyTest.class.getSimpleName());
        final byte[] bytes = resource.bytes("openssl-rsaprivatekey-3072.pem");

        final Pem pem = Pem.parse(bytes);
        {
            final DerParser d1 = new DerParser(pem.getData());
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

                        final Key key1 = new Key(privateKey, Key.Type.PRIVATE, RSA, Key.Format.PEM);
                        System.out.println(key1);
                    }
                }
            }
        }
    }

    @Ignore
    @Test
    public void test4() throws Exception {
        final Resource resource = Resource.resource(BeginPrivateKeyTest.class.getSimpleName());
        final byte[] bytes = resource.bytes("openssl-rsaprivatekey-3072.pem");
        final RSAPrivateCrtKey key = (RSAPrivateCrtKey) Key.decode(bytes).getKey();

        final DerWriter d4 = new DerWriter();
        d4.integer(ZERO);
        d4.integer(key.getModulus());
        d4.integer(key.getPublicExponent());
        d4.integer(key.getPrivateExponent());
        d4.integer(key.getPrimeP());
        d4.integer(key.getPrimeQ());
        d4.integer(key.getPrimeExponentP());
        d4.integer(key.getPrimeExponentQ());
        d4.integer(key.getCrtCoefficient());

        final DerWriter d3b = new DerWriter();
        d3b.writeObject(Asn1Object.sequence(d4.bytes()));

        final DerWriter d3a = new DerWriter();
        d3a.writeObject(Asn1Object.objectIdentifier(Oid.fromString("1.2.840.113549.1.1.1")));
        d3a.writeObject(Asn1Object.nill());


        final DerWriter d2 = new DerWriter();
        d2.integer(ZERO);
        d2.writeObject(Asn1Object.sequence(d3a.bytes()));
        d2.writeObject(Asn1Object.octetString(d3b.bytes()));

        final DerWriter d1 = new DerWriter();
        d1.writeObject(Asn1Object.sequence(d2.bytes()));

        printOctets(d1.bytes());

        final String private_key = Pem.builder()
                .type("PRIVATE KEY")
                .data(d1.bytes())
                .wrap(64)
                .format();

        assertEquals(new String(bytes), private_key);
        Asn1Dump.print(d1.bytes());
    }

    @Ignore
    @Test
    public void test5() throws Exception {
        final Resource resource = Resource.resource(BeginPrivateKeyTest.class.getSimpleName());
        final byte[] bytes = resource.bytes("openssl-rsaprivatekey-3072.pem");
        final RSAPrivateCrtKey key = (RSAPrivateCrtKey) Key.decode(bytes).getKey();


        final byte[] bytes1 = write()
                .sequence(write()
                        .integer(ZERO)
                        .sequence(write()
                                .objectIdentifier(Oid.fromString("1.2.840.113549.1.1.1"))
                                .nill()
                                .bytes())
                        .octetString(write()
                                .sequence(write()
                                        .integer(ZERO)
                                        .integer(key.getModulus())
                                        .integer(key.getPublicExponent())
                                        .integer(key.getPrivateExponent())
                                        .integer(key.getPrimeP())
                                        .integer(key.getPrimeQ())
                                        .integer(key.getPrimeExponentP())
                                        .integer(key.getPrimeExponentQ())
                                        .integer(key.getCrtCoefficient())
                                        .bytes())
                                .bytes())
                        .bytes())
                .bytes();

        printOctets(bytes1);

        final String private_key = Pem.builder()
                .type("PRIVATE KEY")
                .data(bytes1)
                .wrap(64)
                .format();

        assertEquals(new String(bytes), private_key);
        Asn1Dump.print(new DerWriter()
                .sequence(new DerWriter()
                        .integer(ZERO)
                        .sequence(new DerWriter()
                                .objectIdentifier(Oid.fromString("1.2.840.113549.1.1.1"))
                                .nill()
                                .bytes())
                        .octetString(new DerWriter()
                                .sequence(new DerWriter()
                                        .integer(ZERO)
                                        .integer(key.getModulus())
                                        .integer(key.getPublicExponent())
                                        .integer(key.getPrivateExponent())
                                        .integer(key.getPrimeP())
                                        .integer(key.getPrimeQ())
                                        .integer(key.getPrimeExponentP())
                                        .integer(key.getPrimeExponentQ())
                                        .integer(key.getCrtCoefficient())
                                        .bytes())
                                .bytes())
                        .bytes()).bytes());
    }

    @Ignore
    @Test
    public void test6() throws Exception {
        final Resource resource = Resource.resource(BeginPrivateKeyTest.class.getSimpleName());
        final byte[] bytes = resource.bytes("openssl-rsaprivatekey-3072.pem");
        final RSAPrivateCrtKey key = (RSAPrivateCrtKey) Key.decode(bytes).getKey();

        final byte[] encoded = write()
                .sequence(write()
                        .integer(ZERO)
                        .sequence(write()
                                .objectIdentifier(Oid.fromString("1.2.840.113549.1.1.1"))
                                .nill())
                        .octetString(write()
                                .sequence(write()
                                        .integer(ZERO)
                                        .integer(key.getModulus())
                                        .integer(key.getPublicExponent())
                                        .integer(key.getPrivateExponent())
                                        .integer(key.getPrimeP())
                                        .integer(key.getPrimeQ())
                                        .integer(key.getPrimeExponentP())
                                        .integer(key.getPrimeExponentQ())
                                        .integer(key.getCrtCoefficient()))))
                .bytes();

        final String private_key = Pem.builder()
                .type("PRIVATE KEY")
                .data(encoded)
                .wrap(64)
                .format();

        assertEquals(new String(bytes), private_key);
        Asn1Dump.print(encoded);
    }

    private DerWriter write() {
        return new DerWriter();
    }


    private void printOctets(final byte[] bytes) {
        int line = 0;
        for (int i = 0; i < bytes.length; i++) {
            final byte b = bytes[i];
            System.out.printf(" %5s", b);
            if (i % 16 == 15) {
                System.out.println();
                line++;
                if (line > 4) {
                    System.out.println();
                    return;
                }
            }

        }
    }
}
