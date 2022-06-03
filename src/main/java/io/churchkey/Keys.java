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

import org.tomitribe.util.IO;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * The primary factory used to obtain instances of {@link Key}
 *
 * This factory should be favored over calling the constructor's of {@link Key} directly.
 */
public class Keys {

    private Keys() {
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
        return decode(contents.getBytes(StandardCharsets.UTF_8));
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
        for (final Key.Format format : Key.Format.values()) {
            final Key key = format.decode(bytes);
            if (key != null) {
                return key;
            }
        }

        throw new IllegalArgumentException("Cannot decode key: " + new String(bytes));
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
    public static List<Key> decodeSet(final String contents) throws IOException {
        return decodeSet(contents.getBytes(StandardCharsets.UTF_8));
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
    public static List<Key> decodeSet(final File file) throws IOException {
        return decodeSet(IO.readBytes(file));
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
    public static List<Key> decodeSet(final byte[] bytes) {
        for (final Key.Format format : Key.Format.values()) {
            final List<Key> keys = format.decodeSet(bytes);
            if (keys != null) {
                return keys;
            }
        }

        throw new IllegalArgumentException("Cannot decode key: " + new String(bytes));
    }

    /**
     * Encodes the key to the {@link Key.Format} discovered
     * when this key was decoded via {@link #decode(byte[])} or {@link Key.Format#PEM}
     * if this key was created via call to {@link #of(java.security.Key)}.
     *
     * Keys can be exported to any format regardless of which format was present when
     * {@link Keys#decode(byte[])} was called.  This allows keys to be easily converted
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
     * though these files can be read via {@link Keys#decode(byte[])}
     */
    public static byte[] encode(final Key key) {
        return encode(key, key.getFormat());
    }

    /**
     * Encodes the key to the specified {@link Key.Format}
     *
     * Private keys formatted to {@link Key.Format#PEM} will
     * be written in PKCS8 format and start with "BEGIN PRIVATE KEY"
     *
     * Public keys formatted to  {@link Key.Format#PEM} will
     * be written in X509 format and start with "BEGIN PUBLIC KEY"
     *
     * It is currently not possible to encode to PKCS1 formats and create key files
     * starting with "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY" or "BEGIN EC PRIVATE KEY"
     * though these files can be read via {@link Keys#decode(byte[])}
     *
     * @param key The key instance that will be formatted
     * @return
     */
    public static byte[] encode(final Key key, Key.Format format) {
        return format.encode(key);
    }

    /**
     * Creates a {@link Key} instance that encompasses both the public and private keys.  If this Key
     * instance is exported via {@link Key#encode(Key.Format)}} the resulting file will be a private key
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
            return new Key(pair.getPrivate(), pair.getPublic(), Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.PEM);
        }

        if (key instanceof ECPrivateKey) {
            return new Key(pair.getPrivate(), pair.getPublic(), Key.Type.PRIVATE, Key.Algorithm.EC, Key.Format.PEM);
        }

        if (key instanceof RSAPrivateCrtKey) {
            return new Key(pair.getPrivate(), pair.getPublic(), Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.PEM);
        }

        if (key instanceof RSAPrivateKey) {
            return new Key(pair.getPrivate(), pair.getPublic(), Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.PEM);
        }

        throw new UnsupportedOperationException("Unsupported key type: " + key.getClass().getName());

    }

    /**
     * Creates a {@link Key} instance that encompasses the specified {@link java.security.Key}.
     *
     * The key {@link Key.Type} (PUBLIC, PRIVATE) and {@link Key.Algorithm} (RSA, DSA, EC) will
     * be discovered automatically.  The Format will default to PEM.
     *
     * If the key is {@link Key.Type#PRIVATE} and is either {@link Key.Algorithm#RSA} or  {@link Key.Algorithm#DSA}
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
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.PEM);
    }

    private static Key of(final DSAPublicKey key) {
        return new Key(key, Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.PEM);
    }

    private static Key of(final ECPrivateKey key) {
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.EC, Key.Format.PEM);
    }

    private static Key of(final ECPublicKey key) {
        return new Key(key, Key.Type.PUBLIC, Key.Algorithm.EC, Key.Format.PEM);
    }

    private static Key of(final RSAPrivateCrtKey key) {
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.PEM);
    }

    private static Key of(final RSAPrivateKey key) {
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.PEM);
    }

    private static Key of(final RSAPublicKey key) {
        return new Key(key, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.PEM);
    }
}
