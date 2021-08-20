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
package org.tomitribe.churchkey.ssh;

import org.tomitribe.churchkey.Decoder;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.util.Pem;
import org.tomitribe.churchkey.util.Utils;

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

public class SSH2Parser implements Key.Format.Parser {

    @Override
    public Key decode(final byte[] bytes) {
        return new Ssh2PublicKeyDecoder().decode(bytes);
    }

    @Override
    public byte[] encode(final Key key) {
        return new byte[0];
    }

    public static class Ssh2PublicKeyDecoder implements Decoder {

        public Ssh2PublicKeyDecoder() {
        }

        @Override
        public Key decode(final byte[] key) {
            if (!Utils.startsWith("---- BEGIN SSH2 PUBLIC KEY ----", key)) return null;

            final Pem pem = Pem.parse(key);

            final PublicKey publicKey;
            try {
                publicKey = OpenSSHParser.Public.read(pem.getData());
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }

            if (publicKey instanceof RSAPublicKey) {
                return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.SSH2, pem.getAttributes());
            }
            if (publicKey instanceof DSAPublicKey) {
                return new Key(publicKey, Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.SSH2, pem.getAttributes());
            }
            return null;
        }
    }
}
