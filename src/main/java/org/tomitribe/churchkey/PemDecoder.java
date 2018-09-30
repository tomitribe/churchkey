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

import org.tomitribe.churchkey.pem.BeginPublicKey;
import org.tomitribe.churchkey.pem.BeginRsaPrivateKey;
import org.tomitribe.churchkey.pem.BeginRsaPublicKey;
import org.tomitribe.util.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class PemDecoder implements Decoder {

    private final Map<String, Function<byte[],Key>> converters = new HashMap<>();
    {
        converters.put("PRIVATE KEY", this::unimplemented);
        converters.put("PUBLIC KEY", this::publicKey);
        converters.put("RSA PRIVATE KEY", BeginRsaPrivateKey::decode);
        converters.put("RSA PUBLIC KEY", BeginRsaPublicKey::decode);
        converters.put("DSA PRIVATE KEY", this::unimplemented);
        converters.put("DSA PUBLIC KEY", this::unimplemented);
        converters.put("EC PRIVATE KEY", this::unimplemented);
        converters.put("ECDSA PUBLIC KEY", this::unimplemented);
    }

    public PemDecoder() {
    }


    @Override
    public Key decode(final byte[] key) {
        if (!Utils.startsWith("-----", key)) return null;

        final String s = new String(key);
        final String[] parts = s
                .replaceAll(" *\n *", "")
                .replaceAll(" *\r *", "")
                .split("-----(BEGIN|END) |------?");

        final Function<byte[], Key> converter = converters.get(parts[1]);

        if (converter == null) {
            throw new UnsupportedOperationException(String.format("Unsupported PEM format '%s'", parts[1]));
        }

        final byte[] bytes = Base64.decodeBase64(parts[2].getBytes());

        return converter.apply(bytes);
    }


    private Key publicKey(final byte[] key) {

        try {
            final KeyFactory result;
            try {
                result = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
            final KeyFactory factory = result;
            final RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(key));
            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        }

        try {
            final KeyFactory result;
            try {
                result = KeyFactory.getInstance("DSA");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
            final KeyFactory factory = result;
            final DSAPublicKey publicKey = (DSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(key));
            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        }

        try {
            final KeyFactory result;
            try {
                result = KeyFactory.getInstance("EC");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
            final KeyFactory factory = result;
            final ECPublicKey publicKey = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(key));
            return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.EC, Key.Format.PEM);
        } catch (InvalidKeySpecException e) {
            // continue trying other algorithms
        }

        throw new UnsupportedOperationException("Unsupported algorithm or invalid x509 key spec");
    }

    private Key unimplemented(final byte[] key) {
        throw new UnsupportedOperationException();
    }
}
