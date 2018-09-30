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

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;

public class OpenSSHParser implements Key.Format.Parser {

    @Override
    public Key decode(final byte[] bytes) {
        if (!Utils.startsWith("ssh-", bytes)) return null;
        try {

            final PublicKey publicKey = OpenSSH.readSshPublicKey(new String(bytes, "UTF-8"));

            if (publicKey instanceof RSAPublicKey) {
                final RSAPublicKey key = (RSAPublicKey) publicKey;
                return new Key(key, Key.Type.PUBLIC, Key.Algorithm.RSA, Key.Format.OPENSSH);
            }
            if (publicKey instanceof DSAPublicKey) {
                final DSAPublicKey key = (DSAPublicKey) publicKey;
                return new Key(key, Key.Type.PUBLIC, Key.Algorithm.DSA, Key.Format.OPENSSH);
            }

            throw new UnsupportedOperationException("Unknown key type " + publicKey);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public byte[] encode(final Key key) {
        return new byte[0];
    }

    @Override
    public boolean canEncode(final Key key) {
        return false;
    }
}
