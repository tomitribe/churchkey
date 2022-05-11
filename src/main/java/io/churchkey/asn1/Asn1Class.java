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

public enum Asn1Class {
    /**
     * The type is native to ASN.1
     */
    UNIVERSAL(0),

    /**
     * The type is only valid for one specific application
     */
    APPLICATION(1),

    /**
     * Meaning of this type depends on the context (such as within a sequence, set or choice)
     */
    CONTEXT(2),

    /**
     * Defined in private specifications
     */
    PRIVATE(3);

    Asn1Class(final int constant) {
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

    public static Asn1Class fromConstant(int value) {
        // all 4 values are defined
        if ((value < 0) || (value >= values().length)) {
            return null;
        }

        return values()[value];
    }
}
