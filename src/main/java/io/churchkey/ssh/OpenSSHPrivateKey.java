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
package io.churchkey.ssh;

import io.churchkey.dsa.Dsa;
import io.churchkey.ec.Curve;
import io.churchkey.rsa.Rsa;
import io.churchkey.util.Pem;
import io.churchkey.Key;
import io.churchkey.ec.EcPoints;
import io.churchkey.ec.Ecdsa;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import static io.churchkey.ssh.OpenSSHPublicKey.EcPublic.curveName;

public class OpenSSHPrivateKey {

    private OpenSSHPrivateKey() {
    }

    public static Key decode(final byte[] bytes) {
        final Pem pem = Pem.parse(bytes);
        try {

            final KeyInput keyInput = new KeyInput(pem.getData());

            assertString("Auth Magic", "openssh-key-v1", keyInput.readAuthMagic());
            assertString("ciphername", "none", keyInput.readString());
            assertString("kdfname", "none", keyInput.readString());
            assertString("kdf", "", keyInput.readString());
            assertInt("number of keys", 1, keyInput.readInt());

            // Ignore the public key, it is repeated in the private key
            final byte[] sshpublic = keyInput.readBytes();


            keyInput.readInt();

            // a random 32-bit int, repeated
            keyInput.readInt();
            keyInput.readInt();

            final String keyType = keyInput.readString();

            if ("ssh-rsa".equals(keyType)) {
                return readRsaPrivateKey(keyInput);
            }
            if ("ssh-dss".equals(keyType)) {
                return readPrivateDssKey(keyInput);
            }
            if ("ecdsa-sha2-nistp256".equals(keyType)) {
                return readEcdsaPrivateKey(Curve.nistp256, keyInput);
            }
            if ("ecdsa-sha2-nistp384".equals(keyType)) {
                return readEcdsaPrivateKey(Curve.nistp384, keyInput);
            }
            if ("ecdsa-sha2-nistp521".equals(keyType)) {
                return readEcdsaPrivateKey(Curve.nistp521, keyInput);
            }

            throw new UnsupportedOperationException("Unsupported key type: " + keyType);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encode(final Key key) {
        byte[] result;
        try {
            final KeyOutput out = new KeyOutput();

            out.writeAuthMagic("openssh-key-v1");
            out.writeString("none"); // ciphername
            out.writeString("none"); // kdfname
            out.writeString(""); // kdf
            out.writeInt(1); // number of keys

            out.writeBytes(encodePublicKey(key)); // public key
            out.writeBytes(pad(encodePrivateKey(key))); // public key

            result = out.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        final byte[] bytes = result;
        return Pem.builder()
                .type("OPENSSH PRIVATE KEY")
                .wrap(70)
                .data(bytes)
                .format()
                .getBytes();
    }

    private static byte[] pad(final byte[] bytes) {
        final int i = bytes.length % 8;
        if (i == 0) return bytes;

        final int needed = 8 - i;
        final byte[] padding = {
                (byte) 0x01,
                (byte) 0x02,
                (byte) 0x03,
                (byte) 0x04,
                (byte) 0x05,
                (byte) 0x06,
                (byte) 0x07,
        };

        final byte[] padded = new byte[bytes.length + needed];
        System.arraycopy(bytes, 0, padded, 0, bytes.length);
        System.arraycopy(padding, 0, padded, bytes.length, needed);
        return padded;
    }

    private static byte[] encodePublicKey(final Key key) throws IOException {
        if (key.getPublicKey() == null) {
            return new byte[0];
        }

        final java.security.Key publicKey = key.getPublicKey().getKey();
        if (publicKey instanceof RSAPublicKey) {

            return OpenSSHPublicKey.RsaPublic.write((RSAPublicKey) publicKey);

        } else if (publicKey instanceof DSAPublicKey) {

            return OpenSSHPublicKey.DsaPublic.write((DSAPublicKey) publicKey);

        } else if (publicKey instanceof ECPublicKey) {

            final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            final String curveName = curveName(ecPublicKey.getParams());

            return OpenSSHPublicKey.EcPublic.write(ecPublicKey, curveName);
        }

        throw new UnsupportedOperationException("Unsupported key type: " + publicKey.getClass().getName());
    }

    private static byte[] encodePrivateKey(final Key key) throws IOException {
        final KeyOutput out = new KeyOutput();

        final int i = new SecureRandom().nextInt();
        out.writeInt(i);
        out.writeInt(i);

        if (key.getAlgorithm() == Key.Algorithm.RSA) {
            out.writeString("ssh-rsa");
            return writeRsaPrivateKey(key, out);
        }

        if (key.getAlgorithm() == Key.Algorithm.DSA) {
            out.writeString("ssh-dss");
            return writePrivateDssKey(key, out);
        }

        if (key.getAlgorithm() == Key.Algorithm.EC) {
            final ECPrivateKey privateKey = (ECPrivateKey) key.getKey();
            final String curve = curveName(privateKey.getParams());
            out.writeString("ecdsa-sha2-" + curve);
            return writeEcdsaPrivateKey(key, curve, out);
        }

        throw new UnsupportedOperationException("Unsupported key type: " + key.getAlgorithm());
    }

    private static byte[] writePrivateDssKey(final Key key, final KeyOutput out) throws IOException {
        final DSAPublicKey publicKey = (DSAPublicKey) key.getPublicKey().getKey();
        final DSAPrivateKey privateKey = (DSAPrivateKey) key.getKey();

        out.writeBigInteger(privateKey.getParams().getP());
        out.writeBigInteger(privateKey.getParams().getQ());
        out.writeBigInteger(privateKey.getParams().getG());
        out.writeBigInteger(publicKey.getY());
        out.writeBigInteger(privateKey.getX());
        out.writeString(getComment(key));
        return out.toByteArray();
    }

    private static Key readPrivateDssKey(final KeyInput keyInput) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final BigInteger p = keyInput.readBigInteger();
        final BigInteger q = keyInput.readBigInteger();
        final BigInteger g = keyInput.readBigInteger();
        final BigInteger y = keyInput.readBigInteger();
        final BigInteger x = keyInput.readBigInteger();
        final Dsa.Private build = Dsa.Private.builder()
                .p(p)
                .q(q)
                .g(g)
                .x(x)
                .build();

        final DSAPrivateKey privateKey = build.toKey();
        final DSAPublicKey publicKey = build.toPublic().toKey();

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("Comment", keyInput.readString());

        return new Key(privateKey, publicKey, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.OPENSSH, attributes);
    }

    private static byte[] writeRsaPrivateKey(final Key key, final KeyOutput out) throws IOException {
        final RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key.getKey();
        out.writeBigInteger(privateKey.getModulus());
        out.writeBigInteger(privateKey.getPublicExponent());
        out.writeBigInteger(privateKey.getPrivateExponent());
        out.writeBigInteger(privateKey.getCrtCoefficient());
        out.writeBigInteger(privateKey.getPrimeP());
        out.writeBigInteger(privateKey.getPrimeQ());
        out.writeString(getComment(key));
        return out.toByteArray();
    }

    private static String getComment(final Key key) {
        return key.getAttribute("Comment") == null ? "none" : key.getAttribute("Comment");
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


        final Rsa.Private.Builder rsa = Rsa.Private.builder()
                .modulus(modulus)
                .publicExponent(publicExp)
                .privateExponent(privateExp)
                .crtCoefficient(crtCoef)
                .primeP(primeP)
                .primeQ(primeQ)
                .primeExponentP(primeExpP)
                .primeExponentQ(primeExpQ);


        final Rsa.Private build = rsa.build();
        final RSAPrivateCrtKey privateKey = build.toKey();
        final RSAPublicKey publicKey = build.toPublic().toKey();

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("Comment", comment);

        return new Key(privateKey, publicKey, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.OPENSSH, attributes);
    }

    private static byte[] writeEcdsaPrivateKey(final Key key, final String curve, final KeyOutput out) throws IOException {
        if (key.getPublicKey() == null) {
            throw new IllegalStateException("ECPublicKey is missing.  This is required to write an ECPrivateKey to OPENSSH private key format");
        }

        final ECPrivateKey privateKey = (ECPrivateKey) key.getKey();
        final ECPublicKey publicKey = (ECPublicKey) key.getPublicKey().getKey();

        out.writeString(curve);
        out.writeBytes(EcPoints.toBytes(publicKey.getW()));
        out.writeBigInteger(privateKey.getS());
        out.writeString(getComment(key));
        return out.toByteArray();
    }

    private static Key readEcdsaPrivateKey(final Curve curve, final KeyInput keyInput) throws IOException {

        final String curveName = keyInput.readString();

        if (!curve.name().equals(curveName)) {
            throw new IllegalStateException(String.format("Mismatched curve %s does not match key type of ecdsa-sha2-%s", curveName, curve.name()));
        }

        final byte[] q = keyInput.readBytes();

        final ECPoint ecPoint = EcPoints.fromBytes(q);

        final BigInteger d = new BigInteger(1, keyInput.readBytes());

        final Ecdsa.Private build = Ecdsa.Private.builder()
                .curveName(curveName)
                .d(d)
                .x(ecPoint.getAffineX())
                .y(ecPoint.getAffineY())
                .build();

        final ECPrivateKey ecPrivateKey = build.toKey();
        final ECPublicKey publicKey = build.toPublic().toKey();

        final Map<String, String> attributes = new HashMap<String, String>();

        final String comment = keyInput.readString();
        if (comment != null) {
            attributes.put("Comment", comment);
        } else {
            attributes.put("Comment", "");
        }

        return new Key(ecPrivateKey, publicKey, Key.Type.PRIVATE, Key.Algorithm.EC, Key.Format.OPENSSH, attributes);
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

}
