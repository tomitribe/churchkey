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
import org.tomitribe.churchkey.util.Pem;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class BeginPublicKey {

    private BeginPublicKey() {
    }

    public static Key decode(final byte[] bytes) {
        try {
            final KeyFactory factory = KeyFactory.getInstance("RSA");
            final RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(bytes));
            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        try {
            final KeyFactory factory = KeyFactory.getInstance("DSA");
            final DSAPublicKey publicKey = (DSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(bytes));
            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        try {
            final KeyFactory factory = KeyFactory.getInstance("EC");
            final ECPublicKey publicKey = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(bytes));
            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.EC, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        throw new UnsupportedOperationException("Unsupported algorithm or invalid x509 key spec");
    }

    public static byte[] encode(final Key key) {

        final Pem.Builder pem = Pem.builder()
                .type("PUBLIC KEY")
                .wrap(64);

        final java.security.Key value = key.getKey();

        try {
            if (value instanceof RSAPublicKey) {
                final KeyFactory factory = KeyFactory.getInstance("RSA");
                final X509EncodedKeySpec keySpec = factory.getKeySpec(value, X509EncodedKeySpec.class);
                return pem.data(keySpec.getEncoded()).format().getBytes();
            }

            if (value instanceof DSAPublicKey) {
                final KeyFactory factory = KeyFactory.getInstance("DSA");
                final X509EncodedKeySpec keySpec = factory.getKeySpec(value, X509EncodedKeySpec.class);
                return pem.data(keySpec.getEncoded()).format().getBytes();
            }

            if (value instanceof ECPublicKey) {
                final KeyFactory factory = KeyFactory.getInstance("EC");
                final X509EncodedKeySpec keySpec = factory.getKeySpec(value, X509EncodedKeySpec.class);
                return pem.data(keySpec.getEncoded()).format().getBytes();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unsupported key algorithm", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid Key Spec", e);
        }

        throw new UnsupportedOperationException("Unsupported key algorithm " + key.getAlgorithm());
    }

}
