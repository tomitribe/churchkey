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

/**
 * P/C             Value   Description
 * Primitive (P)    0      The contents octets directly encode the element value.
 * Constructed (C)  1      The contents octets contain 0, 1, or more element encodings.
 */
public enum Asn1Construction {
    /**
     * The contents octets directly encode the element value.
     */
    PRIMITIVE(0),
    /**
     * The contents octets contain 0, 1, or more element encodings.
     */
    CONSTRUCTED(1);


    Asn1Construction(final int constant) {
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
     *
     * @param i must be a 0 or 1
     * @return PRIMITIVE if the value is 0, CONSTRUCTED if the value is 1
     */
    public static Asn1Construction fromConstant(final int i) {
        // The resulting value should be 0 or 1
        return Asn1Construction.values()[i];
    }
}
