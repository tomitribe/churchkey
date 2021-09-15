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
        new CurveGenerator().generate();
    }

    public void generate() throws Exception {
        final Jsonb jsonb = JsonbBuilder.newBuilder().build();

        final List<String> categories = Arrays.asList("secg", "nist", "brainpool", "anssi", "x962", "x963", "wtls");

        final List<Curve> list = categories.stream()
                .map(s -> new File("/Users/dblevins/work/J08nY/std-curves/" + s + "/curves.json"))
                .map(file -> readCurves(jsonb, file))
                .map(Curves::getCurves)
                .flatMap(Collection::stream)
                .collect(Collectors.toList());

        final List<Curve> noOid = list.stream()
                .filter(curve -> curve.getOid() == null)
                .collect(Collectors.toList());

        final Map<String, Curve> aliases = new HashMap<>();
        for (final Curve curve : list) {

            final String enumName = getEnumName(curve.getName());

            if (!enumName.equals(curve.getName())) {
                System.out.printf("\n    @Name(\"%s\")%n", curve.getName());
            }

            /*
             * If this is an alias for another curve, construct it as a reference
             */
            if (aliases.containsKey(curve.getName())) {
                final Curve actual = aliases.get(curve.getName());
                System.out.printf("    %s(%s),\n", enumName, getEnumName(actual.getName()));
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

            if (curve.getName().equals("sect571r1")) {
                System.out.print(aliases());
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
        final String oid = curve.getOid() == null ? "null" : String.format("oid(%s)", curve.getOid().replace(".", ", "));

        if (curve.getField().getPoly() == null) {
            final String p = hex(curve.getField().getP());
            System.out.printf("    %s(() -> prime(\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            %s), %s),\n", enumName, p, a, b, x, y, n, cofactor, oid);
        } else {
            final List<Integer> terms = getMiddleTerms(curve);
            final int degree = curve.getField().getDegree();
            System.out.printf("    %s(() -> binary(%s, new int[]{%s},\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            \"%s\",\n" +
                    "            %s), %s),\n", enumName, degree, Join.join(", ", terms), a, b, x, y, n, cofactor, oid);
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
        return raw.replaceAll("^0x", "")
//                .replaceAll("^00", "")
                .toUpperCase();
    }

    private String aliases() {
        return "    nistp192(secp192r1),\n" +
                "    nistp224(secp224r1),\n" +
                "    nistp256(secp256r1),\n" +
                "    nistp384(secp384r1),\n" +
                "    nistp521(secp521r1),\n" +
                "    nistk163(sect163k1),\n" +
                "    nistb163(sect163r2),\n" +
                "    nistk233(sect233k1),\n" +
                "    nistb233(sect233r1),\n" +
                "    nistk283(sect283k1),\n" +
                "    nistb283(sect283r1),\n" +
                "    nistk409(sect409k1),\n" +
                "    nistb409(sect409r1),\n" +
                "    nistk571(sect571k1),\n" +
                "    nistb571(sect571r1),\n";
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

    static final Map<String, String> oids = new HashMap<String, String>();

    static {
        oids.put("23", "1.3.132.0.23");
        oids.put("ansip160k1", "1.3.132.0.9");
        oids.put("ansip160r1", "1.3.132.0.8");
        oids.put("ansip160r2", "1.3.132.0.30");
        oids.put("ansip192k1", "1.3.132.0.31");
        oids.put("ansip224k1", "1.3.132.0.32");
        oids.put("ansip224r1", "1.3.132.0.33");
        oids.put("ansip256k1", "1.3.132.0.10");
        oids.put("ansip384r1", "1.3.132.0.34");
        oids.put("ansip521r1", "1.3.132.0.35");
        oids.put("ansit163k1", "1.3.132.0.1");
        oids.put("ansit163r1", "1.3.132.0.2");
        oids.put("ansit163r2", "1.3.132.0.15");
        oids.put("ansit193r1", "1.3.132.0.24");
        oids.put("ansit193r2", "1.3.132.0.25");
        oids.put("ansit233k1", "1.3.132.0.26");
        oids.put("ansit233r1", "1.3.132.0.27");
        oids.put("ansit239k1", "1.3.132.0.3");
        oids.put("ansit283k1", "1.3.132.0.16");
        oids.put("ansit283r1", "1.3.132.0.17");
        oids.put("ansit409k1", "1.3.132.0.36");
        oids.put("ansit409r1", "1.3.132.0.37");
        oids.put("ansit571k1", "1.3.132.0.38");
        oids.put("ansit571r1", "1.3.132.0.39");
        oids.put("prime192v1", "1.2.840.10045.3.1.1");
        oids.put("prime192v2", "1.2.840.10045.3.1.2");
        oids.put("prime192v3", "1.2.840.10045.3.1.3");
        oids.put("prime239v1", "1.2.840.10045.3.1.4");
        oids.put("prime239v2", "1.2.840.10045.3.1.5");
        oids.put("prime239v3", "1.2.840.10045.3.1.6");
        oids.put("secp112r1", "1.3.132.0.6");
        oids.put("secp112r2", "1.3.132.0.7");
        oids.put("secp128r1", "1.3.132.0.28");
        oids.put("secp128r2", "1.3.132.0.29");
        oids.put("sect113r1", "1.3.132.0.4");
        oids.put("sect113r2", "1.3.132.0.5");
        oids.put("sect131r1", "1.3.132.0.22");
    }
}
