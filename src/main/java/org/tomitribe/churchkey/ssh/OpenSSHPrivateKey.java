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
package org.tomitribe.churchkey.ssh;

import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.util.Pem;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.HashMap;
import java.util.Map;

public class OpenSSHPrivateKey {

    private OpenSSHPrivateKey() {
    }

    public static Key decode(final byte[] bytes) {
        final Pem pem = Pem.parse(bytes);
        return decodeBlob(pem.getData());
    }

    public static Key decodeBlob(final byte[] bytes) {
        try {

            final KeyInput keyInput = new KeyInput(bytes);

            assertString("Auth Magic", "openssh-key-v1", keyInput.readAuthMagic());
            assertString("ciphername", "none", keyInput.readString());
            assertString("kdfname", "none", keyInput.readString());
            assertString("kdf", "", keyInput.readString());
            assertInt("number of keys", 1, keyInput.readInt());

            // Ignore the public key, it is repeated in the private key
            final byte[] sshpublic = keyInput.readBytes();


            keyInput.readInt();
            final KeyInput privateKeyKeyInput = keyInput;

            // a random 32-bit int, repeated
            privateKeyKeyInput.readInt();
            privateKeyKeyInput.readInt();

            final String keyType = privateKeyKeyInput.readString();

            if ("ssh-rsa".equals(keyType)) {
                return readRsaPrivateKey(privateKeyKeyInput);
            }
            if ("ssh-dss".equals(keyType)) {
                return readPrivateDssKey(privateKeyKeyInput);
            }

            throw new UnsupportedOperationException("Unsupported key type: " + keyType);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static Key readPrivateDssKey(final KeyInput keyInput) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final BigInteger p = keyInput.readBigInteger();
        final BigInteger q = keyInput.readBigInteger();
        final BigInteger g = keyInput.readBigInteger();
        final BigInteger unknown = keyInput.readBigInteger();
        final BigInteger x = keyInput.readBigInteger();

        final DSAPrivateKeySpec spec = new DSAPrivateKeySpec(x, p, q, g);

        final KeyFactory result = KeyFactory.getInstance("DSA");
        final PrivateKey publicKey = result.generatePrivate(spec);

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("comment", keyInput.readString());

        return new Key(publicKey, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.OPENSSH, attributes);
    }

    private static Key readRsaPrivateKey(final KeyInput keyInput) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        final BigInteger modulus = keyInput.readBigInteger();
        final BigInteger publicExp = keyInput.readBigInteger();
        final BigInteger privateExp = keyInput.readBigInteger();
        final BigInteger crtCoef = keyInput.readBigInteger();
        final BigInteger primeP = keyInput.readBigInteger();
        final BigInteger primeQ = keyInput.readBigInteger();
        final String comment = keyInput.readString();

        final BigInteger one = BigInteger.valueOf(1);
        final BigInteger primeExpP = privateExp.mod(primeP.subtract(one));
        final BigInteger primeExpQ = privateExp.mod(primeQ.subtract(one));


        final RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, primeP, primeQ, primeExpP, primeExpQ, crtCoef);

        final KeyFactory result = KeyFactory.getInstance("RSA");
        final PrivateKey privateKey = result.generatePrivate(spec);

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("comment", comment);

        // TODO make Key.Format.OPENSSH and move to into OpenSSHParser
        return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.OPENSSH, attributes);
    }

    public static void assertString(final String name, final String expected, final String actual) {
        if (!expected.equals(actual)) {
            throw new IllegalArgumentException(String.format("Expected %s of '%s'. Found '%s'", name, expected, actual));
        }
    }

    public static void assertInt(final String name, final int expected, final int actual) {
        if (expected != actual) {
            throw new IllegalArgumentException(String.format("Expected %s of '%s'. Found '%s'", name, expected, actual));
        }
    }

    public static byte[] encode(final Key key) {
        return null;
    }

}