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
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.Objects;

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

    public static DerWriter write() {
        return new DerWriter();
    }

    public DerWriter integer(final BigInteger value) {
        integer(Objects.requireNonNull(value, "No value").toByteArray());
        return this;
    }

    public DerWriter integer(final int value) {
        return integer(BigInteger.valueOf(value));
    }

    public DerWriter sequence(final DerWriter derWriter) {
        return sequence(derWriter.bytes());
    }

    public DerWriter sequence(final byte[] bytes) {
        writeObject(Asn1Object.sequence(bytes));
        return this;
    }

    public DerWriter any(final DerWriter derWriter) {
        return any(derWriter.bytes());
    }

    public DerWriter any(final byte[] bytes) {
        writeObject(new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.ANY, true, bytes.length, bytes));
        return this;
    }

    public DerWriter bolean(final DerWriter derWriter) {
        return bolean(derWriter.bytes());
    }

    public DerWriter bolean(final byte[] bytes) {
        writeObject(new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.BOOLEAN, true, bytes.length, bytes));
        return this;
    }

    /**
     * The integer is always considered to be positive, so if the first byte is less than 0, we pad with a zero to make it
     * positive
     *
     * @param  bytes       {@link BigInteger} bytes
     */
    public void integer(byte... bytes) {
        integer(bytes, 0, Utils.length(bytes));
    }

    /**
     * The integer is always considered to be positive, so if the first byte is less than 0, we pad with a zero to make it
     * positive
     *
     * @param  bytes       {@link BigInteger} bytes
     * @param  off         Offset in bytes data
     * @param  len         Number of bytes to write
     */
    public void integer(byte[] bytes, int off, int len) {
        try {
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
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private boolean isPositive(byte b) {
        return (b & 0x80) == 0;
    }

    public DerWriter octetString(final DerWriter derWriter) {
        return octetString(derWriter.bytes());
    }

    public DerWriter octetString(final byte[] bytes) {
        return writeObject(Asn1Object.octetString(bytes));
    }

    public DerWriter octetString(final BigInteger integer) {
        return octetString(integer.toByteArray());
    }

    public DerWriter bitString(final byte[] bytes) {
        return writeObject(Asn1Object.bitString(bytes));
    }

    public DerWriter objectIdentifier(final Oid oid) {
        return writeObject(Asn1Object.objectIdentifier(oid));
    }

    public DerWriter nill() {
        return writeObject(Asn1Object.nill());
    }

    public DerWriter writeObject(Asn1Object obj) {
        Objects.requireNonNull(obj, "No ASN.1 object");

        final byte tagValue = obj.getTag().toDer();
        return writeObject(tagValue, obj.getLength(), obj.getValue());
    }

    public DerWriter writeObject(byte tag, int len, byte... data) {
        try {
            write(tag & 0xFF);
            writeLength(len);
            write(data, 0, len);
            return this;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
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

    public byte[] bytes() {
        if (this.out instanceof ByteArrayOutputStream) {
            return ((ByteArrayOutputStream) this.out).toByteArray();
        } else {
            throw new UncheckedIOException(new IOException("The underlying stream is not a byte[] stream"));
        }
    }
}
