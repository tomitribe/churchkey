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
import org.tomitribe.churchkey.Utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
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

    @Override
    public Key decode(final byte[] bytes) {
        if (!Utils.startsWith("ssh-", bytes)) return null;
        try {

            final PublicKey publicKey = OpenSSH.readSshPublicKey(new String(bytes, "UTF-8"));

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

    @Override
    public byte[] encode(final Key key) {
        return new byte[0];
    }

    public static class OpenSSH {

        public static String formatSshPublicKey(final PublicKey publicKey, final String comment) throws IOException {
            if (publicKey instanceof RSAPublicKey) {

                final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                final String encodedKey = base64(encodeRsaPublicKey(rsaPublicKey));
                return String.format("ssh-rsa %s %s%n", encodedKey, comment);

            } else if (publicKey instanceof DSAPublicKey) {

                final DSAPublicKey dSAPublicKey = (DSAPublicKey) publicKey;
                final String encodedKey = base64(encodeDsaPublicKey(dSAPublicKey));
                return String.format("ssh-dss %s %s%n", encodedKey, comment);
            }

            throw new UnsupportedOperationException("PublicKey type unsupported: " + publicKey.getClass().getName());
        }

        private static String base64(byte[] src) {
            return Base64.getEncoder().encodeToString(src);
        }

        public static byte[] encodeRsaPublicKey(final RSAPublicKey key) throws IOException {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeString(out, "ssh-rsa");
            writeBigInt(out, key.getPublicExponent());
            writeBigInt(out, key.getModulus());
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
        public static byte[] encodeDsaPublicKey(final DSAPublicKey key) throws IOException {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            writeString(out, "ssh-dss");
            writeBigInt(out, key.getParams().getP());
            writeBigInt(out, key.getParams().getQ());
            writeBigInt(out, key.getParams().getG());
            writeBigInt(out, key.getY());
            return out.toByteArray();
        }

        private static void writeBigInt(final OutputStream out, final BigInteger m) throws IOException {
            writeByteBlock(out, m.toByteArray());
        }

        private static void writeString(final OutputStream out, final String strign) throws IOException {
            writeByteBlock(out, strign.getBytes("UTF-8"));
        }

        private static void writeByteBlock(final OutputStream out, final byte[] data) throws IOException {
            encodeUInt32(data.length, out);
            out.write(data);
        }

        public static void encodeUInt32(int value, OutputStream out) throws IOException {
            byte[] tmp = new byte[4];
            tmp[0] = (byte) ((value >>> 24) & 0xff);
            tmp[1] = (byte) ((value >>> 16) & 0xff);
            tmp[2] = (byte) ((value >>> 8) & 0xff);
            tmp[3] = (byte) (value & 0xff);
            out.write(tmp);
        }

        public static PublicKey readSshPublicKey(final String sshPublicKeyFileContents) throws IOException, GeneralSecurityException {

            final String[] parts = sshPublicKeyFileContents.split(" +");
            final byte[] bytes1 = parts[1].getBytes();
            final byte[] bytes = Base64.getDecoder().decode(bytes1);

            return decode4253PublicKey(bytes);
        }

        public static PublicKey decode4253PublicKey(final byte[] bytes1) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            final InputStream keyData = new ByteArrayInputStream(bytes1);

            final String algorithm = readString(keyData);

            if (algorithm.equals("ssh-rsa")) {

                return readRsaPublicKey(keyData);

            } else if (algorithm.equals("ssh-dss")) {

                return readDsaPublicKey(keyData);
            }

            throw new UnsupportedOperationException("");
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
        private static PublicKey readRsaPublicKey(final InputStream keyData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            final BigInteger e = readBigInt(keyData);
            final BigInteger n = readBigInt(keyData);

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
        private static PublicKey readDsaPublicKey(final InputStream keyData) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            final BigInteger p = readBigInt(keyData);
            final BigInteger q = readBigInt(keyData);
            final BigInteger g = readBigInt(keyData);
            final BigInteger y = readBigInt(keyData);

            final DSAPublicKeySpec keySpec = new DSAPublicKeySpec(y, p, q, g);
            final KeyFactory dsa = KeyFactory.getInstance("DSA");
            return dsa.generatePublic(keySpec);
        }

        public static BigInteger readBigInt(final InputStream s) throws IOException {
            return new BigInteger(readByteBlock(s));
        }

        public static String readString(final InputStream s) throws IOException {
            return new String(readByteBlock(s));
        }

        private static byte[] readByteBlock(final InputStream s) throws IOException {
            int len = decodeInt(s);
            byte[] bytes = new byte[len];
            readFully(s, bytes);
            return bytes;
        }

        private static int decodeInt(final InputStream s) throws IOException {
            byte[] bytes = {0, 0, 0, 0};
            readFully(s, bytes);
            return ((bytes[0] & 0xFF) << 24)
                    | ((bytes[1] & 0xFF) << 16)
                    | ((bytes[2] & 0xFF) << 8)
                    | (bytes[3] & 0xFF);
        }

        /**
         * Read the requested number of bytes or fail if there are not enough left.
         *
         * @param input  where to read input from
         * @param buffer destination
         * @throws IOException  if there is a problem reading the file
         * @throws EOFException if the number of bytes read was incorrect
         */
        public static void readFully(InputStream input, byte[] buffer) throws IOException {
            readFully(input, buffer, 0, buffer.length);
        }

        /**
         * Read the requested number of bytes or fail if there are not enough left.
         *
         * @param input  where to read input from
         * @param buffer destination
         * @param offset initial offset into buffer
         * @param length length to read, must be &ge; 0
         * @throws IOException  if there is a problem reading the file
         * @throws EOFException if the number of bytes read was incorrect
         */
        public static void readFully(InputStream input, byte[] buffer, int offset, int length) throws IOException {
            int actual = read(input, buffer, offset, length);
            if (actual != length) {
                throw new EOFException("Premature EOF - expected=" + length + ", actual=" + actual);
            }
        }

        /**
         * Read as many bytes as possible until EOF or achieved required length
         *
         * @param input  where to read input from
         * @param buffer destination
         * @param offset initial offset into buffer
         * @param length length to read - ignored if non-positive
         * @return actual length read; may be less than requested if EOF was reached
         * @throws IOException if a read error occurs
         */
        public static int read(InputStream input, byte[] buffer, int offset, int length) throws IOException {
            for (int remaining = length, curOffset = offset; remaining > 0; ) {
                int count = input.read(buffer, curOffset, remaining);
                if (count == -1) { // EOF before achieved required length
                    return curOffset - offset;
                }

                remaining -= count;
                curOffset += count;
            }

            return length;
        }
    }
}
