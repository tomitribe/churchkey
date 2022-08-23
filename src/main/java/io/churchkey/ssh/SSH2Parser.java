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
package io.churchkey.ssh;

import io.churchkey.Key;
import io.churchkey.util.Pem;
import io.churchkey.util.Utils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static io.churchkey.Key.Algorithm.DSA;
import static io.churchkey.Key.Algorithm.EC;
import static io.churchkey.Key.Algorithm.RSA;
import static io.churchkey.Key.Type.PUBLIC;

public class SSH2Parser implements Key.Format.Parser {

    @Override
    public Key decode(final byte[] bytes) {
        if (!Utils.startsWith("---- BEGIN SSH2 PUBLIC KEY ----", bytes)) return null;

        final Pem pem = Pem.parse(bytes);

        try {
            final KeyInput reader = new KeyInput(pem.getData());

            final String algorithm = reader.readString();

            if (algorithm.equals("ssh-rsa")) {

                final PublicKey publicKey = OpenSSHPublicKey.RsaPublic.read(reader);

                return new Key(publicKey, PUBLIC, RSA, Key.Format.SSH2, pem.getAttributes());

            } else if (algorithm.equals("ssh-dss")) {

                final PublicKey publicKey = OpenSSHPublicKey.DsaPublic.read(reader);

                return new Key(publicKey, PUBLIC, Key.Algorithm.DSA, Key.Format.SSH2, pem.getAttributes());

            } else {
                throw new UnsupportedOperationException("Unsupported key type: " + algorithm);
            }

        } catch (UnsupportedOperationException e) {
            throw e;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public byte[] encode(final Key key) {
        if (!PUBLIC.equals(key.getType())) {
            throw new UnsupportedOperationException("SSH2 encoding only supported for public keys");
        }

        final byte[] bytes;
        try {
            if (RSA.equals(key.getAlgorithm())) {
                bytes = OpenSSHPublicKey.RsaPublic.write((RSAPublicKey) key.getKey());
            } else if (DSA.equals(key.getAlgorithm())) {
                bytes = OpenSSHPublicKey.DsaPublic.write((DSAPublicKey) key.getKey());
            } else if (EC.equals(key.getAlgorithm())) {
                final ECPublicKey ecPublicKey = (ECPublicKey) key.getKey();
                final String curveName = OpenSSHPublicKey.EcPublic.curveName(ecPublicKey.getParams());
                bytes = OpenSSHPublicKey.EcPublic.write(ecPublicKey, curveName);
            } else {
                throw new UnsupportedOperationException("Unsupported key algorithm: " + key.getAlgorithm());
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return Pem.builder()
                .data(bytes)
                .attributes(key.getAttributes())
                .wrap(70)
                .header("---- BEGIN SSH2 PUBLIC KEY ----")
                .footer("---- END SSH2 PUBLIC KEY ----")
                .format()
                .getBytes();
    }

}
