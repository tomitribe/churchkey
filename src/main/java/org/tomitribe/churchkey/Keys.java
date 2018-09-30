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

public class Keys {

    public static Key decode(final byte[] bytes) {
        for (final Key.Format format : Key.Format.values()) {
            if (format.canDecode(bytes)) {
                return format.decode(bytes);
            }
        }

        throw new IllegalArgumentException("Cannot decode key: " + new String(bytes));
    }

    public static byte[] encode(final Key key) {
        return encode(key, key.getFormat());
    }

    public static byte[] encode(final Key key, Key.Format format) {
        return format.encode(key);
    }

    public static PublicKey readPublicKey(final byte[] bytes) {
        try {
            return OpenSSH.readSshPublicKey(new String(bytes, "UTF-8"));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
