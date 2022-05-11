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
package io.churchkey.ssh;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class KeyOutput extends DataOutputStream {

    private final ByteArrayOutputStream baos;

    public KeyOutput() {
        super(new ByteArrayOutputStream());
        baos = (ByteArrayOutputStream) this.out;
    }

    public void writeAuthMagic(final String string) throws IOException {
        write(string.getBytes());
        write('\000');
    }

    public void writeString(final String string) throws IOException {
        writeBytes(string.getBytes(StandardCharsets.UTF_8));
    }

    public void writeBytes(final byte[] bytes) throws IOException {
        writeInt(bytes.length);
        write(bytes);
    }

    public void writeBigInteger(final BigInteger bigInteger) throws IOException {
        writeBytes(bigInteger.toByteArray());
    }

    public byte[] toByteArray() {
        return baos.toByteArray();
    }
}
