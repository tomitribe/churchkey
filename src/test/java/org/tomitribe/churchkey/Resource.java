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
package org.tomitribe.churchkey;

import org.tomitribe.util.IO;

import java.io.IOException;
import java.net.URL;

public class Resource {

    private final URL base;

    public Resource(final Class base, final String string) {
        this.base = requireResource(base.getClassLoader().getResource(string), string);
    }

    public Resource(final URL base) {
        this.base = base;
    }

    public static Resource resource(int rsaBits, int shaBits) {
        return new Resource(Resource.class, String.format("rsa%s-sha%s/%s", rsaBits, shaBits, "data.txt"));
    }

    public byte[] bytes(final String name) throws IOException {
        final URL privateDerUrl = new URL(base, name);
        requireResource(privateDerUrl, name);
        return IO.readBytes(privateDerUrl);
    }

    private static URL requireResource(final URL resource, final String name) {
        if (resource == null) throw new IllegalStateException(name + " not found");
        return resource;
    }
}
