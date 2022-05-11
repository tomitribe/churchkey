/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.churchkey;

import java.io.IOException;
import java.util.Base64;

public class Scenario extends Resource {

    private final int shaBits;
    private final int rsaBits;

    public Scenario(final int rsaBits, final int shaBits) {
        super(Scenario.class, String.format("rsa%s-sha%s/%s", rsaBits, shaBits, "data.txt"));
        this.shaBits = shaBits;
        this.rsaBits = rsaBits;
    }

    public int getShaBits() {
        return shaBits;
    }

    public int getRsaBits() {
        return rsaBits;
    }

    public byte[] signature() throws IOException {

        final String signature = new String(this.bytes("signature.txt")).trim();
        return Base64.getDecoder().decode(signature.getBytes());
    }

    public byte[] data() throws IOException {
        return this.bytes("data.txt");
    }
}
