/*
 * Copyright 2021 Tomitribe and community
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.churchkey.util;

public class Bytes {
    private Bytes() {
    }

    public static byte[] trim(byte[] bytes) {
        if (bytes == null) return null;
        while (true) {
            if (bytes.length == 0) return bytes;
            if (bytes[0] != 0) return bytes;
            final byte[] trim = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trim, 0, trim.length);
            bytes = trim;
        }
    }
    public static byte[] trim2(byte[] bytes) {
        if (bytes == null) return null;
        while (true) {
            if (bytes.length == 0) return bytes;
            if (bytes[0] != 0) return bytes;
            if (bytes.length < 2) return bytes;
            if (bytes[1] < 0) return bytes;
            final byte[] trim = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trim, 0, trim.length);
            bytes = trim;
        }
    }
}
