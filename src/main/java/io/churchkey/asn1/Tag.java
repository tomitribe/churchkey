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
package io.churchkey.asn1;

import lombok.Data;

@Data
public class Tag {

    private final Asn1Class clazz;
    private final Asn1Construction construction;
    private final Asn1Type type;

    public byte toDer() {
        final int clas = clazz.getConstant() << 6;
        final int cons = construction.getConstant() << 5;
        final int type = this.type.getConstant();
        // Merge them together into one bit string
        return (byte) (clas | cons | type);
    }

    /**
     * <P>
     * The first byte in DER encoding is made of following fields
     * </P>
     *
     * <pre>
     *-------------------------------------------------
     *|Bit 8|Bit 7|Bit 6|Bit 5|Bit 4|Bit 3|Bit 2|Bit 1|
     *-------------------------------------------------
     *|  Class    | CF  |        Type                 |
     *-------------------------------------------------
     * </pre>
     *
     * @param  tag The original DER encoded byte
     * @return The decoded tag value
     */
    public static Tag fromDer(final int tag) {
        final int clas = (tag & 0b11000000) >> 6;
        final int cons = (tag & 0b00100000) >> 5;
        final int type = (tag & 0b00011111);

        return new Tag(
                Asn1Class.fromConstant(clas),
                Asn1Construction.fromConstant(cons),
                Asn1Type.fromConstant(type)
        );
    }
}
