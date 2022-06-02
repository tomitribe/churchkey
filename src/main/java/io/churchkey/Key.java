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
package io.churchkey;

import io.churchkey.dsa.Dsa;
import io.churchkey.jwk.JwkParser;
import io.churchkey.pem.PemParser;
import io.churchkey.rsa.Rsa;
import io.churchkey.ssh.OpenSSHParser;
import io.churchkey.ssh.SSH2Parser;
import org.tomitribe.util.IO;

import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Wraps an instance of {@link java.security.Key} and provides additional metadata
 * such as {@link Key.Type} (PUBLIC, PRIVATE),  {@link Key.Algorithm} (RSA, DSA, EC)
 * and {@link Key.Format} (PEM, JWK, OPENSSH, SSH2) to identify the type of encoding
 * that was read to create this key.
 *
 * The {@link java.security.Key} this {@link Key} instance wraps can be obtained via
 * {@link Key#getKey()} and cast to any of {@link java.security.interfaces.RSAPublicKey}, 
 * {@link java.security.interfaces.RSAPrivateKey}, {@link java.security.interfaces.RSAPrivateCrtKey},
 * {@link java.security.interfaces.DSAPrivateKey}, {@link java.security.interfaces.DSAPublicKey},
 * {@link java.security.interfaces.ECPrivateKey} or {@link java.security.interfaces.ECPublicKey}
 * depending on the value of  {@link Key.Type} and  {@link Key.Algorithm}
 *
 * {@link Key} instances can be exported to any desired format via {@link Key#encode(Format)}
 *
 * If the key is of type {@link Key.Type#PRIVATE} is either {@link Key.Algorithm#RSA} or
 * {@link Key.Algorithm#DSA}, the public key can be obtained via {@link Key#getPublicKey()}.  If
 * the key is a {@link Key.Type#PRIVATE} {@link Key.Algorithm#EC} key the public key can be
 * obtained if the public key information was present in the encoded key file used to decode
 * and create this {@link Key} instance.  For most key formats, the public key information
 * will be present in the private key file.
 *
 * Some key formats such as OPENSSH, SSH2 and JWK allow for comments or additional
 * metadata to be in they key file.  This information will be parsed and placed into
 * the {@link Key#getAttributes()} map where it can be easily accessed.
 *
 * For example, given the following JWK:
 *
 * <code>
 * {
 *   "kty": "EC",
 *   "crv": "P-256",
 *   "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
 *   "use": "enc",
 *   "kid": "orangekey"
 * }
 * </code>
 *
 * One could obtain the "kid" and "use" fields as follows:
 *
 * <code>
 * final String kid = key.getAttribute("kid");
 * final String use = key.getAttribute("use");
 * </code>
 */
public class Key {

    private final java.security.Key key;
    private final Type type;
    private final Algorithm algorithm;
    private final Format format;
    private final Map<String, String> attributes = new HashMap<>();
    private final Key publicKey;

    /**
     * Avoid constructing Key instances directly and instead favor any of {@link Key#decode(byte[])},
     * {@link Key#of(java.security.Key)} or {@link Key#of(KeyPair)}
     *
     * This constructor may change or become private without notice.
     */
    public Key(final java.security.Key key, final java.security.PublicKey publicKey, final Type type, final Algorithm algorithm, final Format format) {
        this(key, publicKey, type, algorithm, format, new HashMap<>());
    }

    /**
     * Avoid constructing Key instances directly and instead favor any of {@link Key#decode(byte[])},
     * {@link Key#of(java.security.Key)} or {@link Key#of(KeyPair)}
     *
     * This constructor may change or become private without notice.
     */
    public Key(final java.security.Key key, final Type type, final Algorithm algorithm, final Format format) {
        this(key, type, algorithm, format, new HashMap<>());
    }

    /**
     * Avoid constructing Key instances directly and instead favor any of {@link Key#decode(byte[])},
     * {@link Key#of(java.security.Key)} or {@link Key#of(KeyPair)}
     *
     * This constructor may change or become private without notice.
     */
    public Key(final java.security.Key key, final Type type, final Algorithm algorithm, final Format format, final Map<String, String> attributes) {
        this(key, null, type, algorithm, format, attributes);
    }

    /**
     * Avoid constructing Key instances directly and instead favor any of {@link Key#decode(byte[])},
     * {@link Key#of(java.security.Key)} or {@link Key#of(KeyPair)}
     *
     * This constructor may change or become private without notice.
     */
    public Key(final java.security.Key key, final java.security.PublicKey publicKey, final Type type,
               final Algorithm algorithm, final Format format, final Map<String, String> attributes) {
        Objects.requireNonNull(key);
        Objects.requireNonNull(type);
        Objects.requireNonNull(algorithm);
        Objects.requireNonNull(format);
        Objects.requireNonNull(attributes);
        this.key = key;
        this.type = type;
        this.algorithm = algorithm;
        this.format = format;
        this.attributes.putAll(attributes);
        this.publicKey = publicKey(key, publicKey, algorithm, format, attributes);
    }

    /**
     * Inspects the contents of the supplied string, assumes it to be the contents
     * of a valid key file, determines what key format was supplied and then parses
     * it returning a {@link Key} instance.
     *
     * The {@link Key} instance can be used to query what type of key was found
     * (Public or Private), what format was discovered (PEM, JWK, OpenSSH, SSH2)
     * and the actual {@link java.security.Key} instance.
     * @param contents the contents of any valid PEM, JWK, OpenSSH or SSH2 key file
     * @return a {@link Key} instance that has metadata and wraps the parsed {@link java.security.Key}
     */
    public static Key decode(final String contents) throws IOException {
        return decode(contents.getBytes(UTF_8));
    }

    /**
     * Inspects the contents of the supplied file, determines what key file
     * format was supplied and then parses it returning a {@link Key} instance.
     *
     * The {@link Key} instance can be used to query what type of key was found
     * (Public or Private), what format was discovered (PEM, JWK, OpenSSH, SSH2)
     * and the actual {@link java.security.Key} instance.
     * @param file a valid PEM, JWK, OpenSSH or SSH2 key file
     * @return a {@link Key} instance that has metadata and wraps the parsed {@link java.security.Key}
     */
    public static Key decode(final File file) throws IOException {
        return decode(IO.readBytes(file));
    }

    /**
     * Inspects the contents of the supplied bytes, determines what key file
     * format was supplied and then parses it returning a {@link Key} instance.
     *
     * The {@link Key} instance can be used to query what type of key was found
     * (Public or Private), what format was discovered (PEM, JWK, OpenSSH, SSH2)
     * and the actual {@link java.security.Key} instance.
     * @param bytes contents of any valid PEM, JWK, OpenSSH or SSH2 key file
     * @return a {@link Key} instance that has metadata and wraps the parsed {@link java.security.Key}
     */
    public static Key decode(final byte[] bytes) {
        for (final Format format : Format.values()) {
            final Key key = format.decode(bytes);
            if (key != null) {
                return key;
            }
        }

        throw new IllegalArgumentException("Cannot decode key: " + new String(bytes));
    }

    /**
     * Encodes the key to the {@link Format} discovered
     * when this key was decoded via {@link #decode(byte[])} or {@link Format#PEM}
     * if this key was created via call to {@link #of(java.security.Key)}.
     *
     * Keys can be exported to any format regardless of which format was present when
     * {@link Key#decode(byte[])} was called.  This allows keys to be easily converted
     * from one format to another.
     *
     * Private keys formatted to {@link Format#PEM} will
     * be written in PKCS8 format and start with "BEGIN PRIVATE KEY"
     *
     * Public keys formatted to  {@link Format#PEM} will
     * be written in X509 format and start with "BEGIN PUBLIC KEY"
     *
     * It is currently not possible to encode to PKCS1 formats and create key files
     * starting with "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY" or "BEGIN EC PRIVATE KEY"
     * though these files can be read via {@link Key#decode(byte[])}
     */
    public static byte[] encode(final Key key) {
        return encode(key, key.getFormat());
    }

    /**
     * Encodes the key to the specified {@link Format}
     *
     * Private keys formatted to {@link Format#PEM} will
     * be written in PKCS8 format and start with "BEGIN PRIVATE KEY"
     *
     * Public keys formatted to  {@link Format#PEM} will
     * be written in X509 format and start with "BEGIN PUBLIC KEY"
     *
     * It is currently not possible to encode to PKCS1 formats and create key files
     * starting with "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY" or "BEGIN EC PRIVATE KEY"
     * though these files can be read via {@link Key#decode(byte[])}
     *
     * @param key The key instance that will be formatted
     * @return
     */
    public static byte[] encode(final Key key, Format format) {
        return format.encode(key);
    }

    /**
     * Creates a {@link Key} instance that encompasses both the public and private keys.  If this Key
     * instance is exported via {@link Key#encode(Format)}} the resulting file will be a private key
     * file that includes both the public and private key data.
     *
     * The key Algorithm (RSA, DSA, EC) will be discovered automatically.  The Format will default
     * to PEM.  The key Type will be set as PRIVATE.  The corresponding public key can be obtained
     * via {@link Key#getPublicKey()}
     *
     * This method is largely a convenience method for formatting {@link java.security.KeyPair} instances.
     * For example:
     * <code>
     * final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
     * final KeyPair pair = generator.generateKeyPair();
     *
     * final byte[] openssh = Keys.of(pair).format(OPENSSH);
     * </code>
     */
    public static Key of(final KeyPair pair) {
        Objects.requireNonNull(pair);

        final PrivateKey key = pair.getPrivate();

        if (key instanceof DSAPrivateKey) {
            return new Key(pair.getPrivate(), pair.getPublic(), Type.PRIVATE, Algorithm.DSA, Format.PEM);
        }

        if (key instanceof ECPrivateKey) {
            return new Key(pair.getPrivate(), pair.getPublic(), Type.PRIVATE, Algorithm.EC, Format.PEM);
        }

        if (key instanceof RSAPrivateCrtKey) {
            return new Key(pair.getPrivate(), pair.getPublic(), Type.PRIVATE, Algorithm.RSA, Format.PEM);
        }

        if (key instanceof RSAPrivateKey) {
            return new Key(pair.getPrivate(), pair.getPublic(), Type.PRIVATE, Algorithm.RSA, Format.PEM);
        }

        throw new UnsupportedOperationException("Unsupported key type: " + key.getClass().getName());

    }

    /**
     * Creates a {@link Key} instance that encompasses the specified {@link java.security.Key}.
     *
     * The key {@link Type} (PUBLIC, PRIVATE) and {@link Algorithm} (RSA, DSA, EC) will
     * be discovered automatically.  The Format will default to PEM.
     *
     * If the key is {@link Type#PRIVATE} and is either {@link Algorithm#RSA} or  {@link Algorithm#DSA}
     * the public key information will be calculated and can be obtained via {@link Key#getPublicKey()}
     * via {@link Key#getPublicKey()}
     *
     * This method is largely a convenience method for formatting {@link java.security.Key} instances.
     * For example:
     * <code>
     * final RSAPrivateCrtKey myKey = ...
     * final byte[] jwk = Keys.of(myKey).format(JWK);
     * </code>
     */
    public static Key of(final java.security.Key key) {
        Objects.requireNonNull(key);

        if (key instanceof RSAPrivateCrtKey) return of((RSAPrivateCrtKey) key);

        if (key instanceof RSAPrivateKey) return of((RSAPrivateKey) key);

        if (key instanceof RSAPublicKey) return of((RSAPublicKey) key);

        if (key instanceof DSAPrivateKey) return of((DSAPrivateKey) key);

        if (key instanceof DSAPublicKey) return of((DSAPublicKey) key);

        if (key instanceof ECPrivateKey) return of((ECPrivateKey) key);

        if (key instanceof ECPublicKey) return of((ECPublicKey) key);

        throw new UnsupportedOperationException("Unsupported key type: " + key.getClass().getName());
    }

    private static Key of(final DSAPrivateKey key) {
        return new Key(key, Type.PRIVATE, Algorithm.DSA, Format.PEM);
    }

    private static Key of(final DSAPublicKey key) {
        return new Key(key, Type.PUBLIC, Algorithm.DSA, Format.PEM);
    }

    private static Key of(final ECPrivateKey key) {
        return new Key(key, Type.PRIVATE, Algorithm.EC, Format.PEM);
    }

    private static Key of(final ECPublicKey key) {
        return new Key(key, Type.PUBLIC, Algorithm.EC, Format.PEM);
    }

    private static Key of(final RSAPrivateCrtKey key) {
        return new Key(key, Type.PRIVATE, Algorithm.RSA, Format.PEM);
    }

    private static Key of(final RSAPrivateKey key) {
        return new Key(key, Type.PRIVATE, Algorithm.RSA, Format.PEM);
    }

    private static Key of(final RSAPublicKey key) {
        return new Key(key, Type.PUBLIC, Algorithm.RSA, Format.PEM);
    }

    private Key publicKey(final java.security.Key key, PublicKey publicKey, final Algorithm algorithm,
                          final Format format, final Map<String, String> attributes) {
        if (!(key instanceof PrivateKey)) {
            return null;
        }

        if (publicKey == null) {
            // For RSA and DSA it's fairly easy to calculate it
            if (algorithm == Algorithm.RSA && key instanceof RSAPrivateCrtKey) {
                final RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) key;
                publicKey = Rsa.Public.builder()
                        .publicExponent(rsaPrivateCrtKey.getPublicExponent())
                        .modulus(rsaPrivateCrtKey.getModulus())
                        .build().toKey();
            } else if (algorithm == Algorithm.DSA && key instanceof DSAPrivateKey) {
                final DSAPrivateKey privateKey = (DSAPrivateKey) key;
                publicKey = Dsa.Private.builder()
                        .x(privateKey.getX())
                        .p(privateKey.getParams().getP())
                        .g(privateKey.getParams().getG())
                        .q(privateKey.getParams().getQ())
                        .build()
                        .toPublic()
                        .toKey();
            }
        }

        if (publicKey != null) {
            return new Key(publicKey, Type.PUBLIC, algorithm, format, attributes);
        }

        return null;
    }

    /**
     * Returns the Public Key corresponding to this Private key.
     *
     * If the key is of type {@link Key.Type#PRIVATE} is either {@link Key.Algorithm#RSA} or
     * {@link Key.Algorithm#DSA}, the public key information will be discovered through the encoded
     * file when {@link Key#decode(byte[])} is called.  If not found this information will be
     * calculated.
     *
     * If the key is a {@link Key.Type#PRIVATE} {@link Key.Algorithm#EC} key the public key can be
     * obtained only if the public key information was present in the encoded key file used to decode
     * and create this {@link Key} instance.  For most key formats, the EC public key information
     * will be present in the EC private key file.
     *
     * @return the public key corresponding to this private key or null if no public key information exists
     * @throws IllegalStateException if this is not a private key
     */
    public Key getPublicKey() {
        if (type == Type.PRIVATE) return publicKey;
        throw new IllegalStateException(type + " keys do not have public keys");
    }

    /**
     * Some key formats such as OPENSSH, SSH2 and JWK allow for comments or additional
     * metadata to be in they key file.  This information will be parsed and placed into
     * the {@link Key#getAttributes()} map where it can be easily accessed.
     *
     * For example, given the following JWK:
     *
     * <code>
     * {
     *   "kty": "EC",
     *   "crv": "P-256",
     *   "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
     *   "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
     *   "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
     *   "use": "enc",
     *   "kid": "orangekey"
     * }
     * </code>
     *
     * One could obtain the "kid" and "use" fields as follows:
     *
     * <code>
     * final String kid = key.getAttribute("kid");
     * final String use = key.getAttribute("use");
     * </code>
     *
     * A key's attributes will be exported to the target {@link Format}
     * when calling {@link #encode(Format)} if that target format supports
     * it.
     *
     * <ul>
     *     <li>{@link Format#JWK} support any attribute.  All attributes added to the {@link Key} will be present in the encoded JWK.</li>
     *     <li>{@link Format#SSH2} support any attribute.  All attributes added to the {@link Key} will be present in the encoded SSH2 key.</li>
     *     <li>{@link Format#OPENSSH} supports a standard "Comment" attribute.
     *     All other attributes will be ignored</li>
     *     <li>{@link Format#PEM} files do not support attributes, therefore all attributes will be ignored</li>
     * </ul>
     *
     * @return a modifiable map of attributes found or added to this key instance
     */
    public Map<String, String> getAttributes() {
        return attributes;
    }

    public String getAttribute(final String name) {
        return attributes.get(name);
    }

    public boolean hasAttribute(final String name) {
        return attributes.containsKey(name);
    }

    /**
     * The {@link java.security.Key} this {@link Key} instance wraps can be obtained via
     * {@link Key#getKey()} and cast to any of {@link java.security.interfaces.RSAPublicKey},
     * {@link java.security.interfaces.RSAPrivateKey}, {@link java.security.interfaces.RSAPrivateCrtKey},
     * {@link java.security.interfaces.DSAPrivateKey}, {@link java.security.interfaces.DSAPublicKey},
     * {@link java.security.interfaces.ECPrivateKey} or {@link java.security.interfaces.ECPublicKey}
     * depending on the value of  {@link Key.Type} and  {@link Key.Algorithm}
     *
     * @return
     */
    public java.security.Key getKey() {
        return key;
    }

    public Type getType() {
        return type;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public Format getFormat() {
        return format;
    }

    /**
     * Encodes this key to the target format.  In the case of JWK the returned bytes will
     * be unformatted JSON, not base64 encoded.
     *
     * Keys can be exported to any format regardless of which format was present when
     * {@link Key#decode(byte[])} was called.  This allows keys to be easily converted
     * from one format to another.
     *
     * Private keys formatted to {@link Key.Format#PEM} will
     * be written in PKCS8 format and start with "BEGIN PRIVATE KEY"
     *
     * Public keys formatted to  {@link Key.Format#PEM} will
     * be written in X509 format and start with "BEGIN PUBLIC KEY"
     *
     * It is currently not possible to encode to PKCS1 formats and create key files
     * starting with "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY" or "BEGIN EC PRIVATE KEY"
     * though these files can be read via {@link Key#decode(byte[])}
     *
     * @param format the desired target format.
     * @return the encoded bytes ready to be written as-is to the target file.  For PEM,
     * JWK, OPENSSH and SSH2 this will return UTF-8 bytes.  For future formats such as DER
     * the bytes returned will be binary.
     */
    public byte[] encode(final Format format) {
        return format.encode(this);
    }

    public String toJwk() {
        return new String(encode(Format.JWK), UTF_8);
    }

    public String toPem() {
        return new String(encode(Format.PEM), UTF_8);
    }

    public String toOpenSsh() {
        return new String(encode(Format.OPENSSH), UTF_8);
    }

    public String toSsh2() {
        return new String(encode(Format.SSH2), UTF_8);
    }

    public enum Type {
        /**
         * Indicates the {@link java.security.Key} contained by the {@link Key} instance
         * is assignable to {@link java.security.PublicKey}
         */
        PUBLIC,
        /**
         * Indicates the {@link java.security.Key} contained by the {@link Key} instance
         * is assignable to {@link java.security.PrivateKey}
         */
        PRIVATE,
        /**
         * Indicates the {@link java.security.Key} contained by the {@link Key} instance
         * is a symmetric key.  For {@link Format#JWK} keys this will be anytime the
         * 'kty' is 'oct'
         */
        SECRET
    }

    public enum Algorithm {
        RSA, DSA, EC, OCT;

        public Factory getKeyFactory() {
            if (this == OCT) throw new UnsupportedOperationException();
            try {
                return new Factory(KeyFactory.getInstance(name()));
            } catch (NoSuchAlgorithmException e) {
                throw new UnsupportedAlgorithmException(this, e);
            }
        }
    }

    public enum Format {
        JWK(new JwkParser()),
        OPENSSH(new OpenSSHParser()),
        SSH2(new SSH2Parser()),
        PEM(new PemParser()),
        ;

        private final Parser parser;

        Format(final Parser parser) {
            this.parser = parser;
        }

        public byte[] encode(final Key key) {
            return parser.encode(key);
        }

        public Key decode(final byte[] bytes) {
            return parser.decode(bytes);
        }

        public interface Parser {
            Key decode(final byte[] bytes);

            byte[] encode(final Key key);
        }
    }

    public static class Factory {
        private final KeyFactory keyFactory;

        public Factory(final KeyFactory keyFactory) {
            this.keyFactory = keyFactory;
        }

        public PublicKey generatePublic(final KeySpec keySpec) {
            try {
                return keyFactory.generatePublic(keySpec);
            } catch (InvalidKeySpecException e) {
                throw new InvalidPublicKeySpecException(keySpec, e);
            }
        }

        public PrivateKey generatePrivate(final KeySpec keySpec) {
            try {
                return keyFactory.generatePrivate(keySpec);
            } catch (InvalidKeySpecException e) {
                throw new InvalidPrivateKeySpecException(keySpec, e);
            }
        }
    }

}
