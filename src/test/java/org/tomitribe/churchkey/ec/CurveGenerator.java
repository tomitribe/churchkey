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

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.tomitribe.util.IO;
import org.tomitribe.util.Join;

import javax.json.bind.Jsonb;
import javax.json.bind.JsonbBuilder;
import javax.json.bind.annotation.JsonbProperty;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.tomitribe.churchkey.ec.Curve.getEnumName;

public class CurveGenerator {

    public static void main(String[] args) throws Exception {
//        final ECFieldF2m m = new ECFieldF2m(191, new int[]{190, 188, 184, 176, 160, 128, 64, 63, 62, 60, 56, 48, 32});
        new CurveGenerator().generate();
    }

    public void generate() throws Exception {
        final Jsonb jsonb = JsonbBuilder.newBuilder().build();

        final List<String> categories = Arrays.asList("secg", "nist", "brainpool", "anssi", "x962", "x963");

        final List<Curve> list = categories.stream()
                .map(s -> new File("/Users/dblevins/work/J08nY/std-curves/" + s + "/curves.json"))
                .map(file -> readCurves(jsonb, file))
                .map(Curves::getCurves)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());

        final Map<String, Curve> aliases = new HashMap<>();
        for (final Curve curve : list) {
            /*
             * If this is an alias for another curve, construct it as a reference
             */
            if (aliases.containsKey(curve.getName())) {
                final Curve actual = aliases.get(curve.getName());
                System.out.printf("    %s(%s),\n", getEnumName(curve.getName()), getEnumName(actual.getName()));
                continue;
            }

            /*
             * Track the aliases for this curve and print the full curve
             */
            if (curve.getAliases() != null) {
                curve.getAliases().stream()
                        .map(s -> s.replaceAll(".*/", ""))
                        .forEach(s -> aliases.put(s, curve));
            }
            aliases.put(curve.getName(), curve);
            try {
                generate(curve);
            } catch (UnsupportableBinaryCurveException e) {
                // skip this curve
            } catch (Exception e) {
                throw new IllegalStateException(curve.getName(), e);
            }
        }
    }

    private Curves readCurves(final Jsonb jsonb, final File file) {
        try {
            return jsonb.fromJson(IO.read(file), Curves.class);
        } catch (FileNotFoundException e) {
            throw new UncheckedIOException(e);
        }
    }

    private void generate(final Curve curve) {
        final String enumName = getEnumName(curve.getName());
        final String a = hex(curve.getParams().getA());
        final String b = hex(curve.getParams().getB());
        final String x = hex(curve.getGenerator().getX());
        final String y = hex(curve.getGenerator().getY());
        final String n = hex(curve.getOrder());
        final String cofactor = curve.getCofactor();

        if (curve.getField().getPoly() == null) {
            final String p = hex(curve.getField().getP());
            System.out.printf("    %s(() -> prime(\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            %s)),\n", enumName, p, a, b, x, y, n, cofactor);
        } else {
            final List<Integer> terms = getMiddleTerms(curve);
            final int degree = curve.getField().getDegree();
            System.out.printf("    %s(() -> binary(%s, new int[]{%s},\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            %s)),\n", enumName, degree, Join.join(", ", terms), a, b, x, y, n, cofactor);
        }
    }

    private List<Integer> getMiddleTerms(final Curve curve) {
        final List<Integer> terms = curve.getField().getPoly().stream()
                .map(Poly::getPower)
                .collect(Collectors.toList());

        if (terms.size() != 3 && terms.size() != 5) {
            throw new UnsupportableBinaryCurveException("Invalid reduction polynomial.  Should have 3 or 5 terms." +
                    "  Found " + terms.size() + ", Curve " + curve.getName());
        }
        // Remove first and last
        terms.remove(0);
        terms.remove(terms.size() - 1);
        return terms;
    }

    private String hex(final Value x) {
        final String raw = x.getRaw();
        return hex(raw);
    }

    private String hex(final String raw) {
        return raw.replaceAll("^0x", "").toUpperCase();
    }


    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    public static class Curves {
        @JsonbProperty("name")
        private String name;

        @JsonbProperty("desc")
        private String description;

        @JsonbProperty("curves")
        private List<Curve> curves;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    public static class Curve {

        @JsonbProperty("name")
        private String name;

        @JsonbProperty("desc")
        private String description;

        @JsonbProperty("oid")
        private String oid;

        @JsonbProperty("field")
        private Field field;

        @JsonbProperty("form")
        private String form;

        @JsonbProperty("params")
        private Params params;

        @JsonbProperty("generator")
        private Generator generator;

        @JsonbProperty("order")
        private String order;

        @JsonbProperty("cofactor")
        private String cofactor;

        @JsonbProperty("aliases")
        private List<String> aliases;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    public static class Field {
        @JsonbProperty("type")
        private String type;

        @JsonbProperty("p")
        private String p;

        @JsonbProperty("bits")
        private int bits;

        @JsonbProperty("poly")
        private List<Poly> poly;

        @JsonbProperty("degree")
        private int degree;

        @JsonbProperty("basis")
        private String basis;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    public static class Poly {
        @JsonbProperty("power")
        private int power;

        @JsonbProperty("coeff")
        private String coeff;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    public static class Params {
        @JsonbProperty("a")
        private Value a;

        @JsonbProperty("b")
        private Value b;
    }


    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    public static class Generator {
        @JsonbProperty("x")
        private Value x;

        @JsonbProperty("y")
        private Value y;
    }


    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    @EqualsAndHashCode(onlyExplicitlyIncluded = true)
    public static class Value {
        @JsonbProperty("raw")
        private String raw;
    }

    public static class UnsupportableBinaryCurveException extends IllegalArgumentException {
        public UnsupportableBinaryCurveException(final String s) {
        }
    }
}
