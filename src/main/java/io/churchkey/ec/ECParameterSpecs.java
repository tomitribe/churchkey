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
package io.churchkey.ec;

import org.tomitribe.util.Hex;
import org.tomitribe.util.Join;
import org.tomitribe.util.PrintString;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.List;

public class ECParameterSpecs {
    private ECParameterSpecs() {
    }

    public static boolean equals(final ECParameterSpec expected, final ECParameterSpec actual) {
        if (expected.getCofactor() != actual.getCofactor()) return false;
        if (!expected.getOrder().equals(actual.getOrder())) return false;
        if (!expected.getCurve().getA().equals(actual.getCurve().getA())) return false;
        if (!expected.getCurve().getB().equals(actual.getCurve().getB())) return false;
        if (!expected.getGenerator().getAffineX().equals(actual.getGenerator().getAffineX())) return false;
        if (!expected.getGenerator().getAffineY().equals(actual.getGenerator().getAffineY())) return false;

        if (expected.getCurve().getField() instanceof ECFieldFp) {
            final ECFieldFp expectedField = (ECFieldFp) expected.getCurve().getField();
            final ECFieldFp actualField = (ECFieldFp) actual.getCurve().getField();
            if (!expectedField.getP().equals(actualField.getP())) return false;
        }

        if (expected.getCurve().getField() instanceof ECFieldF2m) {
            if (expected.getCurve().getField() instanceof ECFieldF2m) {
                final ECFieldF2m expectedField = (ECFieldF2m) expected.getCurve().getField();
                final ECFieldF2m actualField = (ECFieldF2m) actual.getCurve().getField();
                if (!expectedField.getReductionPolynomial().equals(actualField.getReductionPolynomial())) return false;
            }
        }

        return true;
    }

    public static String toString(final ECParameterSpec spec) {
        final PrintString out = new PrintString();
        final String x = hex(spec.getGenerator().getAffineX());
        final String y = hex(spec.getGenerator().getAffineY());
        final String a = hex(spec.getCurve().getA());
        final String b = hex(spec.getCurve().getB());
        final String n = hex(spec.getOrder());
        final int cofactor = spec.getCofactor();

        final ECField field = spec.getCurve().getField();


        if (field instanceof ECFieldFp) {
            final ECFieldFp fp = (ECFieldFp) field;
            final String p = hex(fp.getP());
            out.printf("prime(\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    %s), %s)\n", p, a, b, x, y, n, cofactor, null);
        } else if (field instanceof ECFieldF2m) {
            final ECFieldF2m binary = (ECFieldF2m) field;

            final int m = binary.getM();
            final List<Integer> terms = new ArrayList<>();
            for (final int i : binary.getMidTermsOfReductionPolynomial()) {
                terms.add(i);
            }

            out.printf("binary(%s, new int[]{%s},\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    \"%s\",\n" +
                    "    %s), %s)\n", m, Join.join(", ", terms), a, b, x, y, n, cofactor, null);
        }


        return out.toString();
    }

    public static String hex(final BigInteger bi) {
        return Hex.toString(bi.toByteArray()).toUpperCase();
    }
}
