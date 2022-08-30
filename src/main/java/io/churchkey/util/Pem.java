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
package io.churchkey.util;

import lombok.Data;
import org.tomitribe.util.PrintString;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

@Data
public class Pem {

    private final String header;
    private final String footer;
    private final String type;
    private final byte[] data;
    private final int wrap;
    private final Map<String, String> attributes;

    Pem(String header, String footer, String type, byte[] data, int wrap, Map<String, String> attributes) {
        this.header = header;
        this.footer = footer;
        this.type = type;
        this.data = data;
        this.wrap = wrap;
        this.attributes = attributes;
    }

    public static Pem parse(final byte[] bytes) {
        return parse(new String(bytes));
    }

    public static Pem parse(final String string) {
        final List<String> lines = new ArrayList<>(Arrays.asList(string.split("[\r\n]")));

        final String header = lines.remove(0);
        final String footer = lines.remove(lines.size() - 1);

        final Iterator<String> iterator = lines.listIterator();

        final Map<String, String> attributes = new HashMap<>();

        String line = "";
        // Read the attributes
        while (iterator.hasNext()) {
            line = iterator.next();
            if (!line.contains(":")) break;

            final int colon = line.indexOf(":");
            final String name = line.substring(0, colon).trim();
            final String value = line.substring(colon + 1).trim().replaceAll("^\"|\"$", "");
            attributes.put(name, value);
        }

        // Read the base64 encoded data
        final StringBuilder encoded = new StringBuilder();
        encoded.append(line);
        final int wrap = line.length();

        while (iterator.hasNext()) {
            encoded.append(iterator.next());
        }

        final byte[] data = Base64.getDecoder().decode(encoded.toString());

        final String type = getType(header);
        return new Pem(header, footer, type, data, wrap, attributes);
    }

    private static String getType(final String header) {
        return header.replaceAll("^-+ ?BEGIN | ?-+$", "");
    }

    public static Builder builder() {
        return new Builder();
    }

    public String format() {
        final PrintString out = new PrintString();
        out.println(header);

        for (final Map.Entry<String, String> entry : attributes.entrySet()) {
            out.printf("%s: \"%s\"%n", entry.getKey(), entry.getValue());
        }

        {// Write the data as base64 encoded
            final ByteArrayInputStream encoded = new ByteArrayInputStream(Base64.getEncoder().encode(data));
            try {
                final byte[] line = new byte[wrap];
                int length;
                while ((length = encoded.read(line)) != -1) {
                    out.println(new String(line, 0, length));
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        out.println(footer);
        return out.toString();
    }

    public static class Builder {

        private String header;
        private String footer;
        private String type;
        private byte[] data;
        private int wrap = 64;
        private Map<String, String> attributes = new HashMap<>();

        Builder() {
        }

        public Builder type(final String type) {
            this.type = type;
            final String upperCaseType = type.toUpperCase();
            header(String.format("-----BEGIN %s-----", upperCaseType));
            footer(String.format("-----END %s-----", upperCaseType));
            return this;
        }

        /**
         * Base64 encoded data
         */
        public Builder data(final String base64Data) {
            return data(Base64.getDecoder().decode(base64Data));
        }

        /**
         * Unencoded binary data
         */
        public Builder data(final byte[] binaryData) {
            this.data = binaryData;
            return this;
        }

        public Builder attribute(final String name, final String value) {
            this.attributes.put(name, value);
            return this;
        }

        public String format() {
            return build().format();
        }

        public Builder header(String header) {
            this.header = header;
            return this;
        }

        public Builder footer(String footer) {
            this.footer = footer;
            return this;
        }

        public Builder wrap(int wrap) {
            this.wrap = wrap;
            return this;
        }

        public Builder attributes(Map<String, String> attributes) {
            this.attributes = attributes;
            return this;
        }

        public Pem build() {
            return new Pem(header, footer, (type != null) ? type : getType(header), data, wrap, attributes);
        }

        public String toString() {
            return "Pem.Builder(header=" + this.header + ", footer=" + this.footer +
                    ", type=" + this.type + ", data=" + Arrays.toString(this.data) +
                    ", wrap=" + this.wrap + ", attributes=" + this.attributes + ")";
        }
    }
}
