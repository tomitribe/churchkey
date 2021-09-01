/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.tomitribe.churchkey.asn1;

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A bare-minimum DER encoder - just enough so we can encoder signatures and keys data
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DerWriter extends FilterOutputStream {
    private final byte[] lenBytes = new byte[Integer.BYTES];

    public DerWriter() {
        this(256);
    }

    public DerWriter(int initialSize) {
        this(new ByteArrayOutputStream(initialSize));
    }

    public DerWriter(OutputStream stream) {
        super(Objects.requireNonNull(stream, "No output stream"));
    }

    public DerWriter startSequence() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        AtomicBoolean dataWritten = new AtomicBoolean(false);
        @SuppressWarnings("resource")
        DerWriter encloser = this;
        return new DerWriter(baos) {
            @Override
            public void close() throws IOException {
                baos.close();

                if (!dataWritten.getAndSet(true)) { // detect repeated calls and write this only once
                    encloser.writeObject(
                            new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.SEQUENCE, false, baos.size(), baos.toByteArray()));
                }
            }
        };
    }

    public void writeBigInteger(BigInteger value) throws IOException {
        writeBigInteger(Objects.requireNonNull(value, "No value").toByteArray());
    }

    /**
     * The integer is always considered to be positive, so if the first byte is < 0, we pad with a zero to make it
     * positive
     *
     * @param  bytes       {@link BigInteger} bytes
     * @throws IOException If failed to write the bytes
     */
    public void writeBigInteger(byte... bytes) throws IOException {
        writeBigInteger(bytes, 0, Utils.length(bytes));
    }

    /**
     * The integer is always considered to be positive, so if the first byte is < 0, we pad with a zero to make it
     * positive
     *
     * @param  bytes       {@link BigInteger} bytes
     * @param  off         Offset in bytes data
     * @param  len         Number of bytes to write
     * @throws IOException If failed to write the bytes
     */
    public void writeBigInteger(byte[] bytes, int off, int len) throws IOException {
        // Strip leading zeroes
        while (len > 1 && bytes[off] == 0 && isPositive(bytes[off + 1])) {
            off++;
            len--;
        }
        // indicate it is an INTEGER
        write(0x02);
        // Pad with a zero if needed
        if (isPositive(bytes[off])) {
            writeLength(len);
        } else {
            writeLength(len + 1);
            write(0);
        }
        // Write data
        write(bytes, off, len);
    }

    private boolean isPositive(byte b) {
        return (b & 0x80) == 0;
    }

    public void writeObject(Asn1Object obj) throws IOException {
        Objects.requireNonNull(obj, "No ASN.1 object");

        Asn1Type type = obj.getType();
        byte typeValue = type.getTypeValue();
        Asn1Class clazz = obj.getAsn1Class();
        byte classValue = clazz.getClassValue();
        byte tagValue = (byte) (((classValue << 6) & 0xC0) | (typeValue & 0x1F));
        writeObject(tagValue, obj.getLength(), obj.getValue());
    }

    public void writeObject(byte tag, int len, byte... data) throws IOException {
        write(tag & 0xFF);
        writeLength(len);
        write(data, 0, len);
    }

    public void writeLength(int len) throws IOException {
        Utils.checkTrue(len >= 0, "Invalid length: %d", len);

        // short form - MSBit is zero
        if (len <= 127) {
            write(len);
            return;
        }

        Utils.putUInt(len, lenBytes);

        int nonZeroPos = 0;
        for (; nonZeroPos < lenBytes.length; nonZeroPos++) {
            if (lenBytes[nonZeroPos] != 0) {
                break;
            }
        }

        if (nonZeroPos >= lenBytes.length) {
            throw new StreamCorruptedException("All zeroes length representation for len=" + len);
        }

        int bytesLen = lenBytes.length - nonZeroPos;
        write(0x80 | bytesLen); // indicate number of octets
        write(lenBytes, nonZeroPos, bytesLen);
    }

    public byte[] toByteArray() throws IOException {
        if (this.out instanceof ByteArrayOutputStream) {
            return ((ByteArrayOutputStream) this.out).toByteArray();
        } else {
            throw new IOException("The underlying stream is not a byte[] stream");
        }
    }
}
