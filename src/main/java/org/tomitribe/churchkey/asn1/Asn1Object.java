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
import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Asn1Object {

    private final Tag tag;
    private final int length;
    private final byte[] value;

    public Asn1Object(final byte tag, final int len, final byte... data) {
        this(Tag.fromDer(tag), len, data);
    }

    public Asn1Object(final Asn1Class c, final Asn1Type t, final boolean ctored, final int len, final byte... data) {
        this(new Tag(c, ctored ? Asn1Construction.CONSTRUCTED : Asn1Construction.PRIMITIVE, t), len, data);
    }

    public Asn1Object(final Tag tag, final int len, final byte... data) {
        this.tag = tag;
        length = len;
        value = data;
//        System.out.println(this);
    }

    public Tag getTag() {
        return tag;
    }

    public Asn1Class getAsn1Class() {
        return tag.getClazz();
    }

    public Asn1Type getType() {
        return tag.getType();
    }

    public boolean isType(final Asn1Type type) {
        return this.tag.getType().equals(type);
    }

    public Asn1Object assertType(final Asn1Type type) {
        if (!isType(type)) {
            throw new IllegalStateException(String.format("Expected type %s, found %s", type, this.tag.getType()));
        }
        return this;
    }

    public boolean isConstructed() {
        return tag.getConstruction().equals(Asn1Construction.CONSTRUCTED);
    }

    public int getLength() {
        return length;
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
            case VISIBLE_STRING:
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
     * @return BigInteger
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
     * @return Java string
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
            case VISIBLE_STRING:
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

    public Oid asOID() throws IOException {
        Asn1Type typeValue = getType();
        if (Asn1Type.OBJECT_IDENTIFIER.equals(typeValue)) {
            return toOID();
        } else {
            throw new StreamCorruptedException("Invalid DER: object is not an OID: " + typeValue);
        }
    }

    // Does not check that type is OID
    public Oid toOID() throws IOException {
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

            for (int subLen = 1; ; subLen++, curPos++) {
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

        return new Oid(oid);
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

    public static Asn1Object sequence(final byte[] bytes) {
        return new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.SEQUENCE, true, bytes.length, bytes);
    }

    public static Asn1Object octetString(final byte[] bytes) {
        return new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.OCTET_STRING, false, bytes.length, bytes);
    }

    public static Asn1Object nill() {
        return new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.NULL, false, 0);
    }

    public static Asn1Object objectIdentifier(final Oid oid) {
        final byte[] bytes = oid.toBytes();
        return new Asn1Object(Asn1Class.UNIVERSAL, Asn1Type.OBJECT_IDENTIFIER, false, bytes.length, bytes);
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
