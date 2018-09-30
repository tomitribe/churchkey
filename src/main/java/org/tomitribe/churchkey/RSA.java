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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.tomitribe.churchkey;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Utility for RSA keys.
 */
public enum RSA {
    ;

    private static final String RSA = "RSA";

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#8 format.
     */
    public static PrivateKey privateKeyFromPKCS8(final byte[] pkcs8) throws InvalidKeySpecException {
        try {
            final EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pkcs8);
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a private key constructed from the given DER bytes in PKCS#1 format.
     */
    public static PrivateKey privateKeyFromPKCS1(final byte[] pkcs1) throws InvalidKeySpecException {
        try {
            final RSAPrivateCrtKeySpec privateKeySpec = newRSAPrivateCrtKeySpec(pkcs1);
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a public key constructed from the given DER bytes.
     */
    public static PublicKey publicKeyFrom(final byte[] derBytes) throws InvalidKeySpecException {
        try {
            final KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            final EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(derBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // Extracted from:
    // http://oauth.googlecode.com/svn/code/branches/jmeter/jmeter/src/main/java/org/apache/jmeter/protocol/oauth/sampler/PrivateKeyReader.java
    // See p.41 of http://www.emc.com/emc-plus/rsa-labs/pkcs/files/h11300-wp-pkcs-1v2-2-rsa-cryptography-standard.pdf

    /****************************************************************************
     * Amazon Modifications: Copyright 2014 Amazon.com, Inc. or its affiliates. 
     * All Rights Reserved.
     *****************************************************************************
     * Copyright (c) 1998-2010 AOL Inc. 
     *
     * Licensed under the Apache License, Version 2.0 (the "License");
     * you may not use this file except in compliance with the License.
     * You may obtain a copy of the License at
     *
     *     http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software
     * distributed under the License is distributed on an "AS IS" BASIS,
     * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     * See the License for the specific language governing permissions and
     * limitations under the License.
     *
     ****************************************************************************
     * Convert PKCS#1 encoded private key into RSAPrivateCrtKeySpec.
     *
     * <p/>The ASN.1 syntax for the private key with CRT is
     *
     * <pre>
     * -- 
     * -- Representation of RSA private key with information for the CRT algorithm.
     * --
     * RSAPrivateKey ::= SEQUENCE {
     *   version           Version, 
     *   modulus           INTEGER,  -- n
     *   publicExponent    INTEGER,  -- e
     *   privateExponent   INTEGER,  -- d
     *   prime1            INTEGER,  -- p
     *   prime2            INTEGER,  -- q
     *   exponent1         INTEGER,  -- d mod (p-1)
     *   exponent2         INTEGER,  -- d mod (q-1) 
     *   coefficient       INTEGER,  -- (inverse of q) mod p
     *   otherPrimeInfos   OtherPrimeInfos OPTIONAL 
     * }
     * </pre>
     *
     * @param keyInPkcs1 PKCS#1 encoded key
     * @throws java.io.IOException
     */
    private static RSAPrivateCrtKeySpec newRSAPrivateCrtKeySpec(final byte[] keyInPkcs1) throws IOException {
        final DerParser parser = new DerParser(keyInPkcs1);

        final Asn1Object sequence = parser.read();
        if (sequence.getType() != DerParser.SEQUENCE) {
            throw new IllegalArgumentException("Invalid DER: not a sequence");
        }

        // Parse inside the sequence
        final DerParser p = sequence.getParser();

        p.read(); // Skip version
        final BigInteger modulus = p.read().getInteger();
        final BigInteger publicExp = p.read().getInteger();
        final BigInteger privateExp = p.read().getInteger();
        final BigInteger prime1 = p.read().getInteger();
        final BigInteger prime2 = p.read().getInteger();
        final BigInteger exp1 = p.read().getInteger();
        final BigInteger exp2 = p.read().getInteger();
        final BigInteger crtCoef = p.read().getInteger();

        return new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
    }

}
