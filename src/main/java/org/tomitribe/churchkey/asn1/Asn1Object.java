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

import java.io.EOFException;
import java.io.IOException;
import java.io.Serializable;
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Asn1Object implements Serializable, Cloneable {
    // Constructed Flag
    public static final byte CONSTRUCTED = 0x20;

    private static final long serialVersionUID = 4687581744706127265L;

    private Asn1Class objClass;
    private Asn1Type objType;
    private boolean constructed;
    private int length;
    private byte[] value;

    public Asn1Object() {
        super();
    }

    /*
     * <P>The first byte in DER encoding is made of following fields</P> <pre>
     * ------------------------------------------------- |Bit 8|Bit 7|Bit 6|Bit 5|Bit 4|Bit 3|Bit 2|Bit 1|
     * ------------------------------------------------- | Class | CF | Type |
     * ------------------------------------------------- </pre>
     */
    public Asn1Object(byte tag, int len, byte... data) {
        this(Asn1Class.fromDERValue(tag), Asn1Type.fromDERValue(tag), (tag & CONSTRUCTED) == CONSTRUCTED, len, data);
    }

    public Asn1Object(Asn1Class c, Asn1Type t, boolean ctored, int len, byte... data) {
        objClass = c;
        objType = t;
        constructed = ctored;
        length = len;
        value = data;
    }

    public Asn1Class getAsn1Class() {
        return objClass;
    }

    public void setAsn1Class(Asn1Class c) {
        objClass = c;
    }

    public Asn1Type getType() {
        return objType;
    }

    public void setType(Asn1Type y) {
        objType = y;
    }

    public boolean isConstructed() {
        return constructed;
    }

    public void setConstructed(boolean c) {
        constructed = c;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int l) {
        length = l;
    }

    public byte[] getValue() {
        return value;
    }

    // if length is less than value.length then returns copy of it
    public byte[] getPureValueBytes() {
        byte[] bytes = getValue();
        int available = getLength();
        int numBytes = Utils.length(bytes);
        if (numBytes == available) {
            return bytes;
        }

        if (available == 0) {
            return Utils.EMPTY_BYTE_ARRAY;
        }

        byte[] pure = new byte[available];
        System.arraycopy(bytes, 0, pure, 0, available);
        return pure;
    }

    public void setValue(byte[] v) {
        value = v;
    }

    public DerParser createParser() {
        return new DerParser(getValue(), 0, getLength());
    }

    public Object asObject() throws IOException {
        Asn1Type type = getType();
        if (type == null) {
            throw new IOException("No type set");
        }

        switch (type) {
            case INTEGER:
                return asInteger();

            case NUMERIC_STRING:
            case PRINTABLE_STRING:
            case VIDEOTEX_STRING:
            case IA5_STRING:
            case GRAPHIC_STRING:
            case ISO646_STRING:
            case GENERAL_STRING:
            case BMP_STRING:
            case UTF8_STRING:
                return asString();

            case OBJECT_IDENTIFIER:
                return asOID();

            case SEQUENCE:
                return getValue();

            default:
                throw new IOException("Invalid DER: unsupported type: " + type);
        }
    }

    /**
     * Get the value as {@link BigInteger}
     * 
     * @return             BigInteger
     * @throws IOException if type not an {@link Asn1Type#INTEGER}
     */
    public BigInteger asInteger() throws IOException {
        Asn1Type typeValue = getType();
        if (Asn1Type.INTEGER.equals(typeValue)) {
            return toInteger();
        } else {
            throw new IOException("Invalid DER: object is not integer: " + typeValue);
        }
    }

    // does not check if this is an integer
    public BigInteger toInteger() {
        return new BigInteger(getPureValueBytes());
    }

    /**
     * Get value as string. Most strings are treated as Latin-1.
     * 
     * @return             Java string
     * @throws IOException if
     */
    public String asString() throws IOException {
        Asn1Type type = getType();
        if (type == null) {
            throw new IOException("No type set");
        }

        final String encoding;
        switch (type) {
            // Not all are Latin-1 but it's the closest thing
            case NUMERIC_STRING:
            case PRINTABLE_STRING:
            case VIDEOTEX_STRING:
            case IA5_STRING:
            case GRAPHIC_STRING:
            case ISO646_STRING:
            case GENERAL_STRING:
                encoding = "ISO-8859-1";
                break;

            case BMP_STRING:
                encoding = "UTF-16BE";
                break;

            case UTF8_STRING:
                encoding = "UTF-8";
                break;

            case UNIVERSAL_STRING:
                throw new IOException("Invalid DER: can't handle UCS-4 string");

            default:
                throw new IOException("Invalid DER: object is not a string: " + type);
        }

        return new String(getValue(), 0, getLength(), encoding);
    }

    public List<Integer> asOID() throws IOException {
        Asn1Type typeValue = getType();
        if (Asn1Type.OBJECT_IDENTIFIER.equals(typeValue)) {
            return toOID();
        } else {
            throw new StreamCorruptedException("Invalid DER: object is not an OID: " + typeValue);
        }
    }

    // Does not check that type is OID
    public List<Integer> toOID() throws IOException {
        int vLen = getLength();
        if (vLen <= 0) {
            throw new EOFException("Not enough data for an OID");
        }

        List<Integer> oid = new ArrayList<>(vLen + 1);
        byte[] bytes = getValue();
        int val1 = bytes[0] & 0xFF;
        oid.add(Integer.valueOf(val1 / 40));
        oid.add(Integer.valueOf(val1 % 40));

        for (int curPos = 1; curPos < vLen; curPos++) {
            int v = bytes[curPos] & 0xFF;
            if (v <= 0x7F) { // short form
                oid.add(Integer.valueOf(v));
                continue;
            }

            long curVal = v & 0x7F;
            curPos++;

            for (int subLen = 1;; subLen++, curPos++) {
                if (curPos >= vLen) {
                    throw new EOFException("Incomplete OID value");
                }

                if (subLen > 5) { // 32 bit values can span at most 5 octets
                    throw new StreamCorruptedException("OID component encoding beyond 5 bytes");
                }

                v = bytes[curPos] & 0xFF;
                curVal = ((curVal << 7) & 0xFFFFFFFF80L) | (v & 0x7FL);
                if (curVal > Integer.MAX_VALUE) {
                    throw new StreamCorruptedException("OID value exceeds 32 bits: " + curVal);
                }

                if (v <= 0x7F) { // found last octet ?
                    break;
                }
            }

            oid.add(Integer.valueOf((int) (curVal & 0x7FFFFFFFL)));
        }

        return oid;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getAsn1Class(), getType())
               + Boolean.hashCode(isConstructed())
               + getLength()
               + Utils.hashCode(getValue(), 0, getLength());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        Asn1Object other = (Asn1Object) obj;
        return Objects.equals(this.getAsn1Class(), other.getAsn1Class())
                && Objects.equals(this.getType(), other.getType())
                && (this.isConstructed() == other.isConstructed())
                && (this.getLength() == other.getLength())
                && (Utils.diffOffset(this.getValue(), 0, other.getValue(), 0, this.getLength()) < 0);
    }

    @Override
    public Asn1Object clone() {
        try {
            Asn1Object cpy = getClass().cast(super.clone());
            byte[] data = cpy.getValue();
            if (data != null) {
                cpy.setValue(data.clone());
            }
            return cpy;
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Unexpected clone failure: " + e.getMessage(), e);
        }
    }

    @Override
    public String toString() {
        return Objects.toString(getAsn1Class())
               + "/" + getType()
               + "/" + isConstructed()
               + "[" + getLength() + "]"
               + ": " + Utils.toHex(getValue(), 0, getLength(), ':');
    }
}
