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
package org.tomitribe.churchkey;

import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

public class Keys {

    private Keys() {
    }

    public static Key decode(final byte[] bytes) {
        for (final Key.Format format : Key.Format.values()) {
            final Key key = format.decode(bytes);
            if (key != null) {
                return key;
            }
        }

        throw new IllegalArgumentException("Cannot decode key: " + new String(bytes));
    }

    public static byte[] encode(final Key key) {
        return encode(key, key.getFormat());
    }

    public static byte[] encode(final Key key, Key.Format format) {
        return format.encode(key);
    }

    public static Key of(final java.security.Key key) {
        Objects.requireNonNull(key);

        if (key instanceof DSAPrivateKey) return of((DSAPrivateKey) key);

        if (key instanceof DSAPublicKey) return of((DSAPublicKey) key);

        if (key instanceof ECPrivateKey) return of((ECPrivateKey) key);

        if (key instanceof ECPublicKey) return of((ECPublicKey) key);

        if (key instanceof RSAPrivateCrtKey) return of((RSAPrivateCrtKey) key);

        if (key instanceof RSAPrivateKey) return of((RSAPrivateKey) key);

        if (key instanceof RSAPublicKey) return of((RSAPublicKey) key);

        throw new UnsupportedOperationException("Unsupported key type: " + key.getClass().getName());
    }

    public static Key of(final DSAPrivateKey key) {
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.PEM);
    }

    public static Key of(final DSAPublicKey key) {
        return new Key(key, Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.PEM);
    }

    public static Key of(final ECPrivateKey key) {
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.EC, Key.Format.PEM);
    }

    public static Key of(final ECPublicKey key) {
        return new Key(key, Key.Type.PUBLIC, Key.Algorithm.EC, Key.Format.PEM);
    }

    public static Key of(final RSAPrivateCrtKey key) {
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.PEM);
    }

    public static Key of(final RSAPrivateKey key) {
        return new Key(key, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.PEM);
    }

    public static Key of(final RSAPublicKey key) {
        return new Key(key, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.PEM);
    }
}
