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
package io.churchkey.asn1;

public enum Asn1Type {
    ANY(0),
    /**
     * Model logical, two-state variable values
     */
    BOOLEAN(1),
    /**
     * Model integer variable values
     */
    INTEGER(2),
    /**
     * Model binary data of arbitrary length
     */
    BIT_STRING(3),
    /**
     * Model binary data whose length is a multiple of eight
     */
    OCTET_STRING(4),
    /**
     * Indicate effective absence of a sequence element
     */
    NULL(5),
    /**
     * Name information objects
     */
    OBJECT_IDENTIFIER(6),
    
    OBJECT_DESCRIPTOR(7),
    EXTERNAL(8),
    /**
     * Model real variable values (floats)
     */
    REAL(9),
    /**
     * Model values of variables with at least three states
     */
    ENUMERATED(10),
    EMBEDDED_PDV(11),
    UTF8_STRING(12),
    RELATIVE_OID(13),
    TIME(14),
    RESERVED(15),
    /**
     * SEQUENCE Models an ordered collection of variables of different type
     * SEQUENCE OF Models an ordered collection of variables of the same type
     * Both use the same constant 16
     */
    SEQUENCE(16),
    /**
     * SET Model an unordered collection of variables of different types
     * SET OF Model an unordered collection of variables of the same type
     */
    SET(17),
    /**
     * 0,1,2,3,4,5,6,7,8,9, and space
     */
    NUMERIC_STRING(18),
    /**
     * Upper and lower case letters, digits, space, apostrophe,
     * left/right parenthesis, plus sign, comma, hyphen, full stop,
     * solidus, colon, equal sign, question mark
     */
    PRINTABLE_STRING(19),
    /**
     * The Teletex character set in CCITT's T61, space, and delete. Aka T61String
     */
    TELETEX_STRING(20),
    /**
     * The Videotex character set in CCITT's T.100 and T.101, space, and delete
     */
    VIDEOTEX_STRING(21),
    /**
     * International Alphabet 5 (International ASCII)
     */
    IA5_STRING(22),
    UTCTIME(23),
    GENERALIZEDTIME(24),
    /**
     * All registered G sets, and space
     */
    GRAPHIC_STRING(25),
    /**
     * Printing character sets of international ASCII, and space. Aka ISO646String
     */
    VISIBLE_STRING(26),
    /**
     * All registered C and G sets, space and delete
     */
    GENERAL_STRING(27),
    UNIVERSAL_STRING(28),
    /**
     * Models values that are strings of characters from a specified characterset
     */
    CHARACTER_STRING(29),
    BMP_STRING(30);

    Asn1Type(final int constant) {
        /*
         * We rely on the order of the enum values being consistent
         * with their corresponding constants in byte code form
         */
        if (this.ordinal() != constant) {
            throw new IllegalStateException("The enum order was improperly changed in source code");
        }
    }

    public byte getConstant() {
        return (byte) ordinal();
    }

    /**
     * @param  value The &quot;pure&quot; type value - with no extra bits set
     * @return The {@link Asn1Type} value - {@code null} if no match found
     */
    public static Asn1Type fromConstant(int value) {
        if ((value < 0) || (value > values().length)) {
            return null;
        }

        return values()[value];
    }
}
