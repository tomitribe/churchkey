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

import io.churchkey.Key;
import io.churchkey.dsa.Dsa;
import io.churchkey.ec.Curve;
import io.churchkey.ec.ECParameterSpecs;
import io.churchkey.ec.EcPoints;
import io.churchkey.ec.Ecdsa;
import io.churchkey.ec.UnsupportedCurveException;
import io.churchkey.rsa.Rsa;
import io.churchkey.util.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class OpenSSHPublicKey implements Key.Format.Parser {


    @Override
    public List<Key> decodeSet(final byte[] bytes) {
        if (!Utils.startsWith("ssh-", bytes) && !Utils.startsWith("ecdsa-", bytes)) return null;
        return Stream.of(new String(bytes).split("\n"))
                .map(String::trim)
                .filter(s -> s.startsWith("ssh-") || s.startsWith("ecdsa-"))
                .map(s -> decode(s.getBytes()))
                .collect(Collectors.toList());
    }

    @Override
    public Key decode(final byte[] bytes) {
        if (!Utils.startsWith("ssh-", bytes) && !Utils.startsWith("ecdsa-", bytes)) return null;
        try {

            final String[] parts = new String(bytes, StandardCharsets.UTF_8).split(" +");
            final byte[] encoded = parts[1].trim().getBytes();
            final byte[] unencoded = Base64.getDecoder().decode(encoded);

            final Map<String, String> attributes = new HashMap<>();

            if (parts.length == 3) {
                attributes.put("Comment", parts[2].trim());
            }

            final KeyInput reader = new KeyInput(unencoded);

            final String algorithm = reader.readString();

            if (algorithm.equals("ssh-rsa")) {

                return new Key(RsaPublic.read(reader), Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.OPENSSH, attributes);

            } else if (algorithm.equals("ssh-dss")) {

                return new Key(DsaPublic.read(reader), Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.OPENSSH, attributes);

            } else if (algorithm.startsWith("ecdsa-sha2-")) {

                return new Key(EcPublic.read(reader), Key.Type.PUBLIC, Key.Algorithm.EC, Key.Format.OPENSSH, attributes);

            } else {
                throw new UnsupportedOperationException("Unsupported key type: " + algorithm);
            }

        } catch (UnsupportedOperationException e) {
            throw e;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public byte[] encode(final Key key) {
        final java.security.Key publicKey = key.getKey();

        final String comment;
        if (key.getAttributes().containsKey("Comment")) {
            comment = " " + key.getAttribute("Comment");
        } else {
            comment = "";
        }

        try {
            if (publicKey instanceof RSAPublicKey) {

                final RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                final String encodedKey = OpenSSHParser.base64(RsaPublic.write(rsaPublicKey));
                return String.format("ssh-rsa %s%s%n", encodedKey, comment).getBytes();

            } else if (publicKey instanceof DSAPublicKey) {

                final DSAPublicKey dSAPublicKey = (DSAPublicKey) publicKey;
                final String encodedKey = OpenSSHParser.base64(DsaPublic.write(dSAPublicKey));
                return String.format("ssh-dss %s%s%n", encodedKey, comment).getBytes();

            } else if (publicKey instanceof ECPublicKey) {

                final ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                final String curveName = EcPublic.curveName(ecPublicKey.getParams());
                final String encodedKey = OpenSSHParser.base64(EcPublic.write(ecPublicKey, curveName));
                return String.format("ecdsa-sha2-%s %s%s%n", curveName, encodedKey, comment).getBytes();

            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to encode key", e);
        }

        throw new UnsupportedOperationException("PublicKey type unsupported: " + publicKey.getClass().getName());

    }

    @Override
    public byte[] encodeSet(final List<Key> keys) {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (final Key key : keys) {
            try {
                bytes.write(encode(key));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return bytes.toByteArray();
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
    static class RsaPublic {

        static PublicKey read(final KeyInput keyInput) throws IOException {
            return Rsa.Public.builder()
                    .publicExponent(keyInput.readBigInteger())
                    .modulus(keyInput.readBigInteger())
                    .build()
                    .toKey();
        }

        static byte[] write(final RSAPublicKey key) throws IOException {
            final KeyOutput out = new KeyOutput();
            out.writeString("ssh-rsa");
            out.writeBigInteger(key.getPublicExponent());
            out.writeBigInteger(key.getModulus());
            return out.toByteArray();
        }
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
    static class DsaPublic {
        static PublicKey read(final KeyInput key) throws IOException {
            return Dsa.Public.builder()
                    .p(key.readBigInteger())
                    .q(key.readBigInteger())
                    .g(key.readBigInteger())
                    .y(key.readBigInteger())
                    .build()
                    .toKey();
        }

        static byte[] write(final DSAPublicKey key) throws IOException {
            final KeyOutput out = new KeyOutput();
            out.writeString("ssh-dss");
            out.writeBigInteger(key.getParams().getP());
            out.writeBigInteger(key.getParams().getQ());
            out.writeBigInteger(key.getParams().getG());
            out.writeBigInteger(key.getY());
            return out.toByteArray();
        }
    }

    /**
     * Format documented by https://coolaj86.com/articles/the-ssh-public-key-format/
     */
    static class EcPublic {
        static PublicKey read(final KeyInput key) throws IOException {
            final String curveName = key.readString();
            final Curve curve = Curve.resolve(curveName);
            final byte[] bytes = key.readBytes();
            final ECPoint point = EcPoints.fromBytes(bytes);
            return Ecdsa.Public.builder()
                    .curve(curve)
                    .y(point.getAffineY())
                    .x(point.getAffineX())
                    .build()
                    .toKey();
        }

        static byte[] write(final ECPublicKey key, final String curveName) throws IOException {
            final KeyOutput out = new KeyOutput();
            out.writeString("ecdsa-sha2-" + curveName);
            out.writeString(curveName);
            out.writeBytes(EcPoints.toBytes(key.getW()));
            return out.toByteArray();
        }

        public static String curveName(final ECParameterSpec spec) {
            // Try the most common cases first
            if (Curve.nistp256.isEqual(spec)) return Curve.nistp256.name();
            if (Curve.nistp384.isEqual(spec)) return Curve.nistp384.name();
            if (Curve.nistp521.isEqual(spec)) return Curve.nistp521.name();

            for (final Curve curve : Curve.values()) {
                if (!curve.isEqual(spec)) continue;

                final Optional<Curve> nistAlias = curve.getAliases().stream()
                        .filter(curve1 -> curve1.name().startsWith("nist"))
                        .findFirst();

                return nistAlias.orElse(curve).name();
            }

            // Unsupported curve
            // Print the curve information in the exception
            final String s = ECParameterSpecs.toString(spec);
            throw new UnsupportedCurveException(String.format("The specified ECParameterSpec has no known name.  Params:%n%s", s));
        }

    }
}
