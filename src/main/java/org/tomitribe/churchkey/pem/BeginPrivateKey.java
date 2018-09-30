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

import org.tomitribe.churchkey.Key;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class BeginPrivateKey {

    private BeginPrivateKey() {
    }

    public static Key decode(final byte[] bytes) {
        try {
            final KeyFactory factory = KeyFactory.getInstance("RSA");
            final RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(bytes));
            return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        try {
            final KeyFactory factory = KeyFactory.getInstance("DSA");
            final DSAPrivateKey privateKey = (DSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(bytes));
            return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.DSA, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        try {
            final KeyFactory factory = KeyFactory.getInstance("EC");
            final ECPrivateKey privateKey = (ECPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(bytes));
            return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.EC, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        throw new UnsupportedOperationException("Unsupported algorithm or invalid PKCS#8 key spec");
    }

    public static byte[] encode(final Key key) {
        return null;
    }

}
