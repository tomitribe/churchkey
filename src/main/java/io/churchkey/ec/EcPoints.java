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
package io.churchkey.ec;

import io.churchkey.util.Bytes;

import java.math.BigInteger;
import java.security.spec.ECPoint;

import static io.churchkey.util.Utils.toHexString;

public class EcPoints {
    private EcPoints() {
    }

    public static ECPoint fromBytes(final byte[] bytes) {
        if (bytes.length == 0) {
            throw new IllegalStateException("Key data is truncated");
        }

        if (bytes[0] != (byte) 0x04) {
            final byte[] format = {bytes[0]};
            throw new UnsupportedOperationException("Only uncompressed EC points are supported.  Found EC point compression format of " + toHexString(format) + " (hex)");
        }

        final int length = bytes.length - 1;
        final int elements = length / 2; /* x, y */

        if (length != (elements * 2)) { // make sure length is not odd
            throw new IllegalArgumentException(String.format("Invalid EC point data: expected %s bytes, found %s bytes", (2 * elements), length));
        }

        byte[] xp = new byte[elements];
        byte[] yp = new byte[elements];
        System.arraycopy(bytes, 1, xp, 0, elements);
        System.arraycopy(bytes, 1 + elements, yp, 0, elements);

        BigInteger x = new BigInteger(1, xp);
        BigInteger y = new BigInteger(1, yp);
        return new ECPoint(x, y);
    }

    public static byte[] toBytes(final ECPoint point) {
//        byte[] xp = point.getAffineX().toByteArray();
//        byte[] yp = point.getAffineY().toByteArray();
        byte[] xp = Bytes.trim(point.getAffineX().toByteArray());
        byte[] yp = Bytes.trim(point.getAffineY().toByteArray());

        final int max = Math.max(xp.length, yp.length);
        xp = pad(xp, max);
        yp = pad(yp, max);

        final byte[] bytes = new byte[1 + max * 2];
        bytes[0] = 4;
        System.arraycopy(xp, 0, bytes, 1, xp.length);
        System.arraycopy(yp, 0, bytes, 1 + xp.length, yp.length);

        return bytes;
    }

    private static byte[] pad(byte[] bytes, final int max) {
        if (bytes.length == max) return bytes;
        final byte[] padded = new byte[max];
        final int offset = max - bytes.length;
        System.arraycopy(bytes, 0, padded, offset, bytes.length);
        return padded;
    }
}
