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
package org.tomitribe.churchkey.ec;

import lombok.Builder;
import lombok.Data;
import org.tomitribe.swizzle.stream.StreamBuilder;
import org.tomitribe.util.IO;
import org.tomitribe.util.Join;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class AddOids {

    final Map<String, Curve> curves = new HashMap<>();

    public static void main(String[] args) throws Exception {
        new AddOids().main();
    }

    private void main() throws Exception {
        final List<String> categories = Arrays.asList("secg", "nist", "brainpool", "anssi", "x962", "x963");
        final List<File> files = categories.stream()
                .map(s -> new File("/Users/dblevins/work/J08nY/std-curves/" + s + "/curves.json"))
                .collect(Collectors.toList());

        files.stream()
                .map(Curve::parse)
                .flatMap(Collection::stream)
                .forEach(curve -> curves.put(curve.getName(), curve));

        files.forEach(this::checkOids);
    }

    @Data
    @Builder(builderClassName = "Builder")
    public static class Curve {
        private final String name;
        private final String oid;
        @lombok.Builder.Default
        private final List<String> aliases = new ArrayList<String>();
        private final String content;

        public static List<Curve> parse(final File file) {
            try {
                return Stream.of(IO.slurp(file).split("\n    \\{"))
                        .filter(s -> !s.contains("\n  \"name\":"))
                        .map(Curve::parse)
                        .collect(Collectors.toList());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        public static Curve parse(final String string) {
            final Builder builder = Curve.builder().content(string);

            try {
                StreamBuilder.create(IO.read(string))
                        .watch("\"name\": \"", "\"", builder::name)
                        .watch("\"oid\": \"", "\"", builder::oid)
                        .watch("\"aliases\": [", "]", s -> {
                            final List<String> aliases = Stream.of(s.trim().split("\"[^/]+/|[ ,\t\n\"]+"))
                                    .filter(s1 -> s1.length() > 0)
                                    .collect(Collectors.toList());
                            builder.aliases(aliases);
                        })
                        .run();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return builder.build();
        }
    }

    private void checkOids(final File file) {
        try {
            final List<Object> list = Stream.of(IO.slurp(file).split("\n    \\{"))
                    .map(this::addOid)
                    .collect(Collectors.toList());
            final String content = Join.join("\n    {", list);
            IO.copy(IO.read(content), file);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String addOid(final String content) {
        if (content.contains("\"oid\"")) return content;
        if (content.contains("\n  \"name\":")) return content;

        final Curve curve = Curve.parse(content);

        if (curve.getAliases() == null || curve.getAliases().size() == 0) {
            System.out.println("No OID and no aliases: " + curve.getName());
            return content;
        }

        final List<String> oids = curve.getAliases().stream()
                .map(s -> {
                    final Curve alias = curves.get(s);
                    if (alias == null) {
                        System.out.println("Curve not found: " + s);
                    }
                    return alias;
                })
                .filter(Objects::nonNull)
                .map(Curve::getOid)
                .filter(Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());

        if (oids.size() == 0) {
            throw new IllegalStateException("No Aliased OIDs for " + curve.getName());
        }

        if (oids.size() > 1) {
            throw new IllegalStateException("Multiple OIDs for " + curve.getName());
        }

        final String oid = oids.get(0);

        return content.replace("      \"field\": {\n",
                "      \"oid\": \"" + oid + "\",\n" +
                        "      \"field\": {\n"
        );
    }
}
