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

import org.junit.Test;
import org.tomitribe.churchkey.Decoder;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;
import org.tomitribe.churchkey.Resource;
import org.tomitribe.util.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECFieldFp;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class BeginPrivateKeyTest {

    @Test
    public void testDecode1024() throws Exception {
        final Decoder decoder = new PemParser.PemDecoder()::decode;
        final Resource resource = Resource.resource("rsa", 1024, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void testKeysDecode1024() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("rsa", 1024, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void testDecode2048() throws Exception {
        final Decoder decoder = new PemParser.PemDecoder()::decode;
        final Resource resource = Resource.resource("rsa", 2048, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void testKeysDecode2048() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("rsa", 2048, 256);

        assertDecode(decoder, resource);
    }

    @Test
    public void opensslEcPrivateKeyPrime256v1() throws Exception {
        final Resource resources = Resource.resource(this.getClass().getSimpleName());
        final byte[] bytes = resources.bytes("openssl-ecprivatekey-prime256v1.pem");

        final Key key = Keys.decode(bytes);
        final ECPrivateKey privateKey = (ECPrivateKey) key.getKey();

        assertBigInteger("s", privateKey.getS(), "" +
                "883E13AA05A56CC6E23FD9F689D2E743659AD055EA6F3D720707189FE32ACB73");

        final ECFieldFp field = (ECFieldFp) privateKey.getParams().getCurve().getField();
        assertBigInteger("fp", field.getP(), "" +
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

        assertBigInteger("a", privateKey.getParams().getCurve().getA(), "" +
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");

        assertBigInteger("b", privateKey.getParams().getCurve().getB(), "" +
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

        assertBigInteger("x", privateKey.getParams().getGenerator().getAffineX(), "" +
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");

        assertBigInteger("y", privateKey.getParams().getGenerator().getAffineY(), "" +
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

        assertBigInteger("n", privateKey.getParams().getOrder(), "" +
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        assertEquals(1, privateKey.getParams().getCofactor());
    }

    @Test
    public void opensslEcPrivateKeyParameterSpec() throws Exception {
        final Resource resources = Resource.resource(this.getClass().getSimpleName());
        final byte[] bytes = resources.bytes("openssl-ecprivatekey-parameterspec.pem");

        final Key key = Keys.decode(bytes);
        final ECPrivateKey privateKey = (ECPrivateKey) key.getKey();

        assertBigInteger("s", privateKey.getS(), "" +
                "4CBB21276CF0FDD0FF05BCC89B84A5C54C77B12B453DE3D341AD6F51B34A7E06");

        final ECFieldFp field = (ECFieldFp) privateKey.getParams().getCurve().getField();
        assertBigInteger("fp", field.getP(), "" +
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

        assertBigInteger("a", privateKey.getParams().getCurve().getA(), "" +
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");

        assertBigInteger("b", privateKey.getParams().getCurve().getB(), "" +
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

        assertBigInteger("x", privateKey.getParams().getGenerator().getAffineX(), "" +
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");

        assertBigInteger("y", privateKey.getParams().getGenerator().getAffineY(), "" +
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

        assertBigInteger("n", privateKey.getParams().getOrder(), "" +
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        assertEquals(1, privateKey.getParams().getCofactor());
    }

    @Test
    public void javaEcPrivateKeyPrime256v1() throws Exception {
        final Resource resources = Resource.resource(this.getClass().getSimpleName());
        final byte[] bytes = resources.bytes("java-ecprivatekey-prime256v1.pem");

        final Key key = Keys.decode(bytes);
        final ECPrivateKey privateKey = (ECPrivateKey) key.getKey();

        assertBigInteger("s", privateKey.getS(), "" +
                "30C3DEC6AAB43F2230DACF40BFF081BAFC5658DE48716D4C9EE406B57112BE29");

        final ECFieldFp field = (ECFieldFp) privateKey.getParams().getCurve().getField();
        assertBigInteger("fp", field.getP(), "" +
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

        assertBigInteger("a", privateKey.getParams().getCurve().getA(), "" +
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");

        assertBigInteger("b", privateKey.getParams().getCurve().getB(), "" +
                "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

        assertBigInteger("x", privateKey.getParams().getGenerator().getAffineX(), "" +
                "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");

        assertBigInteger("y", privateKey.getParams().getGenerator().getAffineY(), "" +
                "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

        assertBigInteger("n", privateKey.getParams().getOrder(), "" +
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        assertEquals(1, privateKey.getParams().getCofactor());
    }

    private void assertBigInteger(final String name, final BigInteger actual, final String expected) {
        assertEquals(name, expected, toHex(actual));
    }

    private String toHex(final BigInteger bigInteger) {
        return Hex.toString(bigInteger.toByteArray()).toUpperCase().replaceAll("^00", "");
    }

    public void assertDecode(final Decoder decoder, final Resource resource) throws Exception {
        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final byte[] bytes = resource.bytes("private.pkcs8.pem");
        final Key key = decoder.decode(bytes);
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());

        final RSAPrivateCrtKey actual = (RSAPrivateCrtKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getCrtCoefficient(), actual.getCrtCoefficient());
        assertEquals(expected.getPrimeExponentP(), actual.getPrimeExponentP());
        assertEquals(expected.getPrimeExponentQ(), actual.getPrimeExponentQ());
        assertEquals(expected.getPrimeP(), actual.getPrimeP());
        assertEquals(expected.getPrimeQ(), actual.getPrimeQ());
        assertEquals(expected.getPrivateExponent(), actual.getPrivateExponent());
        assertEquals(expected.getModulus(), actual.getModulus());
    }
}