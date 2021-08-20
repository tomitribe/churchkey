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
package org.tomitribe.churchkey.util;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class Utils {

    private Utils() {
    }

    public static boolean startsWith(final String prefix, final byte[] bytes) {
        final byte[] prefixBytes = prefix.getBytes();

        return startsWith(bytes, prefixBytes);
    }

    public static boolean startsWith(final byte[] bytes, final byte[] prefixBytes) {
        if (bytes.length < prefixBytes.length) return false;

        for (int i = 0; i < prefixBytes.length; i++) {
            if (prefixBytes[i] != bytes[i]) return false;
        }

        return true;
    }

    public static byte[] base64Decode(final String s) throws UnsupportedEncodingException {
        return Base64.getDecoder().decode(s.getBytes("UTF-8"));
    }

    public static String base64Encode(final byte[] bytes) throws UnsupportedEncodingException {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
