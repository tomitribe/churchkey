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
package org.tomitribe.churchkey.jwk;

import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Utils;
import org.tomitribe.util.IO;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonReaderFactory;
import javax.json.JsonValue;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class JwkParser implements Key.Format.Parser {

    @Override
    public Key decode(final byte[] bytes) {
        byte[] decoded = normalize(bytes);
        if (!Utils.startsWith("{", decoded)) return null;

        final String rawJson = new String(decoded);

        final HashMap<String, Object> config = new HashMap<>();
        config.put("org.apache.johnzon.buffer-strategy", "BY_INSTANCE");
        final JsonReaderFactory factory = Json.createReaderFactory(config);
        final JsonReader reader = factory.createReader(IO.read(decoded));

        try {
            final JsonObject jsonObject = reader.readObject();
            final JsonObject jwk = getJwk(jsonObject);

            final String kty;

            if (!jwk.containsKey("kty")) {
                throw new MissingKtyException();
            }

            kty = jwk.getString("kty");

            if ("RSA".equals(kty)) {
                return asRsaKey(jwk);
            }

//            if ("DSA".equals(kty)) {
//                return asDsaKey(jwk);
//            }
//
//            if ("EC".equals(kty)) {
//                return asEcKey(jwk);
//            }

            throw new UnsupportedKtyAlgorithmException(kty);
        } catch (Exception e) {
            throw new InvalidJwkException(e, rawJson);
        }
    }

    private Key asRsaKey(final JsonObject jwkObject) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final Jwk jwk = new Jwk(jwkObject);

        final BigInteger modulus = jwk.getBigInteger("n");
        final BigInteger publicExp = jwk.getBigInteger("e");
        final BigInteger privateExp = jwk.getBigInteger("d");
        final BigInteger primeP = jwk.getBigInteger("p");
        final BigInteger primeQ = jwk.getBigInteger("q");
        final BigInteger primeExponentP = jwk.getBigInteger("dp");
        final BigInteger primeExponentQ = jwk.getBigInteger("dq");
        final BigInteger crtCoef = jwk.getBigInteger("qi");

        final RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExp);
        final RSAPrivateCrtKeySpec rsaPrivateKeySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, primeP, primeQ, primeExponentP, primeExponentQ, crtCoef);

        checkPublicKey(rsaPublicKeySpec);
        checkPrivateKey(rsaPrivateKeySpec);

        final KeyFactory result = KeyFactory.getInstance("RSA");

        if (privateExp != null) {
            final PrivateKey privateKey = result.generatePrivate(rsaPrivateKeySpec);
            return new Key(privateKey, Key.Type.PRIVATE, Key.Algorithm.RSA, Key.Format.JWK);
        }

        final PublicKey publicKey = result.generatePublic(rsaPublicKeySpec);
        return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.JWK);
    }


    private void checkPublicKey(final RSAPublicKeySpec spec) {
        final List<String> missing = new ArrayList<>();

        if (spec.getModulus() == null) missing.add("n");
        if (spec.getPublicExponent() == null) missing.add("e");

        if (missing.size() > 0) throw new InvalidJwkKeySpecException("rsa", missing);
    }

    private void checkPrivateKey(final RSAPrivateCrtKeySpec spec) {
        final List<String> missing = new ArrayList<>();

        if (spec.getPrivateExponent() == null) missing.add("d");
        if (spec.getPrimeP() == null) missing.add("p");
        if (spec.getPrimeQ() == null) missing.add("q");
        if (spec.getPrimeExponentP() == null) missing.add("dp");
        if (spec.getPrimeExponentQ() == null) missing.add("dq");
        if (spec.getCrtCoefficient() == null) missing.add("qi");

        /**
         * We want them to supply either all or none of the private key data
         */
        if (missing.size() == 6) return; // they've supplied none - good
        if (missing.size() == 0) return; // they've supplied all - good

        /**
         * They supplied just some.  This doesn't work and isn't likely what they want
         */
        throw new InvalidJwkKeySpecException("rsa", missing);
    }

    private static class Jwk {

        private final JsonObject jwk;

        public Jwk(final JsonObject jwk) {
            this.jwk = jwk;
        }

        public BigInteger getBigInteger(final String name) {
            if (!jwk.containsKey(name)) return null;
            final String string = jwk.getString(name);
            final java.util.Base64.Decoder urlDecoder = java.util.Base64.getUrlDecoder();
            final byte[] bytes = urlDecoder.decode(string);
            return new BigInteger(1, bytes);
        }
    }

    private JsonObject getJwk(final JsonObject jsonObject) {
        if (jsonObject.containsKey("keys")) {
            return getJwkFromJwks(jsonObject);
        }

        if (jsonObject.containsKey("kty")) {
            return jsonObject;
        }

        throw new UnknownJsonFormatFoundException();
    }

    private JsonObject getJwkFromJwks(final JsonObject jwks) {
        final JsonValue keys = jwks.getValue("keys");

        if (keys == null) {
            throw new IllegalArgumentException("Invalid JWKS; 'keys' entry is missing.");
        }

        switch (keys.getValueType()) {
            case ARRAY:
                return getFirstJwk(jwks, keys.asJsonArray());
            case OBJECT:
                return keys.asJsonObject();
            default:
                throw new IllegalArgumentException("Invalid JWKS; 'keys' entry should be an array.");

        }
    }

    private JsonObject getFirstJwk(final JsonObject jwks, final JsonArray keys) {
        if (keys.size() == 0) {
            throw new IllegalArgumentException("Invalid JWKS; 'keys' entry is empty.\n" + jwks.toString());
        }

        final JsonValue value = keys.get(0);

        if (!JsonValue.ValueType.OBJECT.equals(value.getValueType())) {
            throw new IllegalArgumentException("Invalid JWKS; 'keys' array should contain jwk objects.\n" + jwks.toString());
        }

        return value.asJsonObject();
    }

    /**
     * Base64 unencode the jwk key if needed
     */
    private byte[] normalize(final byte[] bytes) {
        // Fun optimization, base64 json objects always happen to
        // start with 'e' due to always beginning with "{" in
        // unencoded form.  If it doesn't start with 'e' then it
        // isn't base64 encoded or isn't a jwk.
        if (!Utils.startsWith("e", bytes)) return bytes;

        return java.util.Base64.getUrlDecoder().decode(bytes);
    }

    @Override
    public byte[] encode(final Key key) {
        return new byte[0];
    }

}
