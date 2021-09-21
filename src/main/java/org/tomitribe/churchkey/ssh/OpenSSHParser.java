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

import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.util.Utils;

import java.util.Base64;

public class OpenSSHParser implements Key.Format.Parser {

    @Override
    public byte[] encode(final Key key) {
        switch (key.getType()) {
            case PUBLIC: {
                return new OpenSSHPublicKey().encode(key);
            }
            case PRIVATE: {
                throw new UnsupportedOperationException("Unsupported key type: " + key.getType());
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


    public static String base64(byte[] src) {
        return Base64.getEncoder().encodeToString(src);
    }
}
