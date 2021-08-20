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
package org.tomitribe.churchkey.ssh;

import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.util.Utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class OpenSSHParser implements Key.Format.Parser {

    public static String formatSshPublicKey(final PublicKey publicKey, final String comment) throws IOException {
        if (publicKey instanceof RSAPublicKey) {

            final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            final String encodedKey = base64(format(rsaPublicKey));
            return String.format("ssh-rsa %s %s%n", encodedKey, comment);

        } else if (publicKey instanceof DSAPublicKey) {

            final DSAPublicKey dSAPublicKey = (DSAPublicKey) publicKey;
            final String encodedKey = base64(format(dSAPublicKey));
            return String.format("ssh-dss %s %s%n", encodedKey, comment);
        }

        throw new UnsupportedOperationException("PublicKey type unsupported: " + publicKey.getClass().getName());
    }

    private static String base64(byte[] src) {
        return Base64.getEncoder().encodeToString(src);
    }

    public static byte[] format(final RSAPublicKey key) throws IOException {
        final KeyOutput out = new KeyOutput();
        out.writeString("ssh-rsa");
        out.writeBigInteger(key.getPublicExponent());
        out.writeBigInteger(key.getModulus());
        return out.toByteArray();
    }

    /**
     * Order determined by https://tools.ietf.org/html/rfc4253#section-6.6
     *
     * The "ssh-dss" key format has the following specific encoding:
     *
     *      string    "ssh-dss"
     *      mpint     p
     *      mpint     q
     *      mpint     g
     *      mpint     y
     *
     */
    public static byte[] format(final DSAPublicKey key) throws IOException {
        final KeyOutput out = new KeyOutput();
        out.writeString("ssh-dss");
        out.writeBigInteger(key.getParams().getP());
        out.writeBigInteger(key.getParams().getQ());
        out.writeBigInteger(key.getParams().getG());
        out.writeBigInteger(key.getY());
        return out.toByteArray();
    }

    @Override
    public byte[] encode(final Key key) {
        return new byte[0];
    }

    @Override
    public Key decode(final byte[] bytes) {

        if (Utils.startsWith("ssh-", bytes)) {
            return new Public().decode(bytes);
        }
        
//        if (Utils.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----", bytes)) {
//            return new Private().decode(bytes);
//        }
        return null;
    }


    public static class Public implements Key.Format.Parser {

        @Override
        public Key decode(final byte[] bytes) {
            if (!Utils.startsWith("ssh-", bytes)) return null;
            try {

                final String[] parts = new String(bytes, "UTF-8").split(" +");
                final byte[] encoded = parts[1].trim().getBytes();
                final byte[] bytes1 = Base64.getDecoder().decode(encoded);

                final PublicKey publicKey = read(bytes1);

                if (publicKey instanceof RSAPublicKey) {
                    final RSAPublicKey key = (RSAPublicKey) publicKey;
                    return new Key(key, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.OPENSSH);
                }
                if (publicKey instanceof DSAPublicKey) {
                    final DSAPublicKey key = (DSAPublicKey) publicKey;
                    return new Key(key, Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.OPENSSH);
                }

                throw new UnsupportedOperationException("Unknown key type " + publicKey);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * Reads a public key in RFC 4253 format
         * @param bytes raw bytes for the key value, not base64 encoded
         */
        public static PublicKey read(final byte[] bytes) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            final KeyInput reader = new KeyInput(bytes);

            final String algorithm = reader.readString();

            if (algorithm.equals("ssh-rsa")) {

                return rsa(reader);

            } else if (algorithm.equals("ssh-dss")) {

                return dss(reader);
            }

            throw new UnsupportedOperationException("Unsupported key type: " + algorithm);
        }

        /**
         * Order determined by https://tools.ietf.org/html/rfc4253#section-6.6
         *
         * The "ssh-rsa" key format has the following specific encoding:
         *
         *      string    "ssh-rsa"
         *      mpint     e
         *      mpint     n
         */
        private static PublicKey rsa(final KeyInput keyInput) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            final BigInteger e = keyInput.readBigInteger();
            final BigInteger n = keyInput.readBigInteger();

            final RSAPublicKeySpec keySpec = new RSAPublicKeySpec(n, e);
            final KeyFactory rsa = KeyFactory.getInstance("RSA");
            return rsa.generatePublic(keySpec);
        }

        /**
         * Order determined by https://tools.ietf.org/html/rfc4253#section-6.6
         *
         * The "ssh-dss" key format has the following specific encoding:
         *
         *      string    "ssh-dss"
         *      mpint     p
         *      mpint     q
         *      mpint     g
         *      mpint     y
         *
         */
        private static PublicKey dss(final KeyInput keyData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            final BigInteger p = keyData.readBigInteger();
            final BigInteger q = keyData.readBigInteger();
            final BigInteger g = keyData.readBigInteger();
            final BigInteger y = keyData.readBigInteger();

            final DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
            final KeyFactory dsa = KeyFactory.getInstance("DSA");
            return dsa.generatePublic(keySpec);
        }

        @Override
        public byte[] encode(final Key key) {
            return new byte[0];
        }
    }
}
