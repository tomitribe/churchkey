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
import io.churchkey.util.Utils;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class OpenSSHParser implements Key.Format.Parser {

    @Override
    public byte[] encode(final Key key) {
        switch (key.getType()) {
            case PUBLIC: {
                return new OpenSSHPublicKey().encode(key);
            }
            case PRIVATE: {
                return OpenSSHPrivateKey.encode(key);
            }
            case SECRET:
                throw new UnsupportedOperationException("Secret keys cannot be exported to PEM format.");
            default:
                throw new UnsupportedOperationException("Unsupported key type: " + key.getType());
        }
    }

    @Override
    public Key decode(final byte[] bytes) {

        if (Utils.startsWith("ssh-", bytes) || Utils.startsWith("ecdsa-", bytes)) {
            return new OpenSSHPublicKey().decode(bytes);
        }

        if (Utils.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----", bytes)) {
            return OpenSSHPrivateKey.decode(bytes);
        }

        return null;
    }

    @Override
    public List<Key> decodeSet(final byte[] bytes) {

        if (Utils.startsWith("ssh-", bytes) || Utils.startsWith("ecdsa-", bytes)) {
            return new OpenSSHPublicKey().decodeSet(bytes);
        }

        if (Utils.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----", bytes)) {
            return Collections.singletonList(OpenSSHPrivateKey.decode(bytes));
        }

        return null;
    }

    @Override
    public byte[] encodeSet(final List<Key> keys) {
        if (keys.size() == 0) {
            throw new IllegalArgumentException("No keys to encode");
        }
        if (keys.size() == 1) {
            return encode(keys.get(0));
        }

        final List<Key> publicKeys = keys.stream()
                .filter(key -> key.getType().equals(Key.Type.PUBLIC))
                .collect(Collectors.toList());

        if (keys.size() != publicKeys.size()) {
            final String message = String.format("Encoding of multiple keys in OpenSSH is only supported for public keys.  " +
                    "Found %s private keys", keys.size() - publicKeys.size());
            throw new UnsupportedOperationException(message);
        }

        return new OpenSSHPublicKey().encodeSet(keys);
    }

    public static String base64(byte[] src) {
        return Base64.getEncoder().encodeToString(src);
    }
}
