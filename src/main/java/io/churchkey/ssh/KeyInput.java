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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;

import static io.churchkey.util.Printers.printer;

public class KeyInput extends DataInputStream {

    public KeyInput(final byte[] bytes) {
        super(new ByteArrayInputStream(bytes));
    }

    public String readAuthMagic() throws IOException {
        final PrintStream string = printer();
        int read = this.read();
        while (read != '\000') {
            if (read == -1) throw new EOFException();
            string.write(read);
            read = this.read();
        }
        return string.toString();
    }

    public String readString() throws IOException {
        return new String(readBytes());
    }

    public byte[] readBytes() throws IOException {
        final byte[] bytes = new byte[((DataInputStream) this).readInt()];
        final int length = this.read(bytes);
        if (length != bytes.length) {
            throw new IOException(String.format("data truncated.  Expected %s bytes, read %n bytes", bytes.length, length));
        }
        return bytes;
    }

    public BigInteger readBigInteger() throws IOException {
        return new BigInteger(readBytes());
    }
}
