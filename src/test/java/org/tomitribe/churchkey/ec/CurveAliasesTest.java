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

import org.junit.Test;
import org.tomitribe.util.Join;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;

public class CurveAliasesTest {


    @Test
    public void secp112r1() throws Exception {
        assertAliases(Curve.secp112r1, "secp112r1", "SECP112R1");
    }

    @Test
    public void secp112r2() throws Exception {
        assertAliases(Curve.secp112r2, "secp112r2", "SECP112R2");
    }

    @Test
    public void secp128r1() throws Exception {
        assertAliases(Curve.secp128r1, "secp128r1", "SECP128R1");
    }

    @Test
    public void secp128r2() throws Exception {
        assertAliases(Curve.secp128r2, "secp128r2", "SECP128R2");
    }

    @Test
    public void secp160k1() throws Exception {
        assertAliases(Curve.secp160k1, "secp160k1", "ansip160k1", "SECP160K1", "ANSIP160K1");
    }

    @Test
    public void secp160r1() throws Exception {
        assertAliases(Curve.secp160r1, "secp160r1", "ansip160r1", "SECP160R1", "ANSIP160R1");
    }

    @Test
    public void secp160r2() throws Exception {
        assertAliases(Curve.secp160r2, "secp160r2", "ansip160r2", "SECP160R2", "ANSIP160R2");
    }

    @Test
    public void secp192k1() throws Exception {
        assertAliases(Curve.secp192k1, "secp192k1", "ansip192k1", "SECP192K1", "ANSIP192K1");
    }

    @Test
    public void secp192r1() throws Exception {
        assertAliases(Curve.secp192r1, "secp192r1", "p192", "nistp192", "prime192v1", "SECP192R1", "P192", "P-192", "NISTP192", "PRIME192V1");
    }

    @Test
    public void secp224k1() throws Exception {
        assertAliases(Curve.secp224k1, "secp224k1", "ansip224k1", "SECP224K1", "ANSIP224K1");
    }

    @Test
    public void secp224r1() throws Exception {
        assertAliases(Curve.secp224r1, "secp224r1", "p224", "nistp224", "ansip224r1", "SECP224R1", "P224", "P-224", "NISTP224", "ANSIP224R1");
    }

    @Test
    public void secp256k1() throws Exception {
        assertAliases(Curve.secp256k1, "secp256k1", "ansip256k1", "SECP256K1", "ANSIP256K1");
    }

    @Test
    public void secp256r1() throws Exception {
        assertAliases(Curve.secp256r1, "secp256r1", "p256", "nistp256", "prime256v1", "SECP256R1", "P256", "P-256", "NISTP256", "PRIME256V1");
    }

    @Test
    public void secp384r1() throws Exception {
        assertAliases(Curve.secp384r1, "secp384r1", "p384", "nistp384", "ansip384r1", "SECP384R1", "P384", "P-384", "NISTP384", "ANSIP384R1");
    }

    @Test
    public void secp521r1() throws Exception {
        assertAliases(Curve.secp521r1, "secp521r1", "p521", "nistp521", "ansip521r1", "SECP521R1", "P521", "P-521", "NISTP521", "ANSIP521R1");
    }

    @Test
    public void sect113r1() throws Exception {
        assertAliases(Curve.sect113r1, "sect113r1", "SECT113R1");
    }

    @Test
    public void sect113r2() throws Exception {
        assertAliases(Curve.sect113r2, "sect113r2", "SECT113R2");
    }

    @Test
    public void sect131r1() throws Exception {
        assertAliases(Curve.sect131r1, "sect131r1", "SECT131R1");
    }

    @Test
    public void sect131r2() throws Exception {
        assertAliases(Curve.sect131r2, "sect131r2", "SECT131R2");
    }

    @Test
    public void sect163k1() throws Exception {
        assertAliases(Curve.sect163k1, "sect163k1", "k163", "nistk163", "ansit163k1", "SECT163K1", "K163", "K-163", "NISTK163", "ANSIT163K1");
    }

    @Test
    public void sect163r1() throws Exception {
        assertAliases(Curve.sect163r1, "sect163r1", "ansit163r1", "SECT163R1", "ANSIT163R1");
    }

    @Test
    public void sect163r2() throws Exception {
        assertAliases(Curve.sect163r2, "sect163r2", "b163", "nistb163", "ansit163r2", "SECT163R2", "B163", "B-163", "NISTB163", "ANSIT163R2");
    }

    @Test
    public void sect193r1() throws Exception {
        assertAliases(Curve.sect193r1, "sect193r1", "ansit193r1", "SECT193R1", "ANSIT193R1");
    }

    @Test
    public void sect193r2() throws Exception {
        assertAliases(Curve.sect193r2, "sect193r2", "ansit193r2", "SECT193R2", "ANSIT193R2");
    }

    @Test
    public void sect233k1() throws Exception {
        assertAliases(Curve.sect233k1, "sect233k1", "k233", "nistk233", "ansit233k1", "SECT233K1", "K233", "K-233", "NISTK233", "ANSIT233K1");
    }

    @Test
    public void sect233r1() throws Exception {
        assertAliases(Curve.sect233r1, "sect233r1", "b233", "nistb233", "ansit233r1", "SECT233R1", "B233", "B-233", "NISTB233", "ANSIT233R1");
    }

    @Test
    public void sect239k1() throws Exception {
        assertAliases(Curve.sect239k1, "sect239k1", "ansit239k1", "SECT239K1", "ANSIT239K1");
    }

    @Test
    public void sect283k1() throws Exception {
        assertAliases(Curve.sect283k1, "sect283k1", "k283", "nistk283", "ansit283k1", "SECT283K1", "K283", "K-283", "NISTK283", "ANSIT283K1");
    }

    @Test
    public void sect283r1() throws Exception {
        assertAliases(Curve.sect283r1, "sect283r1", "b283", "nistb283", "ansit283r1", "SECT283R1", "B283", "B-283", "NISTB283", "ANSIT283R1");
    }

    @Test
    public void sect409k1() throws Exception {
        assertAliases(Curve.sect409k1, "sect409k1", "k409", "nistk409", "ansit409k1", "SECT409K1", "K409", "K-409", "NISTK409", "ANSIT409K1");
    }

    @Test
    public void sect409r1() throws Exception {
        assertAliases(Curve.sect409r1, "sect409r1", "b409", "nistb409", "ansit409r1", "SECT409R1", "B409", "B-409", "NISTB409", "ANSIT409R1");
    }

    @Test
    public void sect571k1() throws Exception {
        assertAliases(Curve.sect571k1, "sect571k1", "k571", "nistk571", "ansit571k1", "SECT571K1", "K571", "K-571", "NISTK571", "ANSIT571K1");
    }

    @Test
    public void sect571r1() throws Exception {
        assertAliases(Curve.sect571r1, "sect571r1", "b571", "nistb571", "ansit571r1", "SECT571R1", "B571", "B-571", "NISTB571", "ANSIT571R1");
    }

    @Test
    public void p192() throws Exception {
        assertAliases(Curve.p192, "secp192r1", "p192", "nistp192", "prime192v1", "SECP192R1", "P192", "P-192", "NISTP192", "PRIME192V1");
    }

    @Test
    public void p224() throws Exception {
        assertAliases(Curve.p224, "secp224r1", "p224", "nistp224", "ansip224r1", "SECP224R1", "P224", "P-224", "NISTP224", "ANSIP224R1");
    }

    @Test
    public void p256() throws Exception {
        assertAliases(Curve.p256, "secp256r1", "p256", "nistp256", "prime256v1", "SECP256R1", "P256", "P-256", "NISTP256", "PRIME256V1");
    }

    @Test
    public void p384() throws Exception {
        assertAliases(Curve.p384, "secp384r1", "p384", "nistp384", "ansip384r1", "SECP384R1", "P384", "P-384", "NISTP384", "ANSIP384R1");
    }

    @Test
    public void p521() throws Exception {
        assertAliases(Curve.p521, "secp521r1", "p521", "nistp521", "ansip521r1", "SECP521R1", "P521", "P-521", "NISTP521", "ANSIP521R1");
    }

    @Test
    public void k163() throws Exception {
        assertAliases(Curve.k163, "sect163k1", "k163", "nistk163", "ansit163k1", "SECT163K1", "K163", "K-163", "NISTK163", "ANSIT163K1");
    }

    @Test
    public void b163() throws Exception {
        assertAliases(Curve.b163, "sect163r2", "b163", "nistb163", "ansit163r2", "SECT163R2", "B163", "B-163", "NISTB163", "ANSIT163R2");
    }

    @Test
    public void k233() throws Exception {
        assertAliases(Curve.k233, "sect233k1", "k233", "nistk233", "ansit233k1", "SECT233K1", "K233", "K-233", "NISTK233", "ANSIT233K1");
    }

    @Test
    public void b233() throws Exception {
        assertAliases(Curve.b233, "sect233r1", "b233", "nistb233", "ansit233r1", "SECT233R1", "B233", "B-233", "NISTB233", "ANSIT233R1");
    }

    @Test
    public void k283() throws Exception {
        assertAliases(Curve.k283, "sect283k1", "k283", "nistk283", "ansit283k1", "SECT283K1", "K283", "K-283", "NISTK283", "ANSIT283K1");
    }

    @Test
    public void b283() throws Exception {
        assertAliases(Curve.b283, "sect283r1", "b283", "nistb283", "ansit283r1", "SECT283R1", "B283", "B-283", "NISTB283", "ANSIT283R1");
    }

    @Test
    public void k409() throws Exception {
        assertAliases(Curve.k409, "sect409k1", "k409", "nistk409", "ansit409k1", "SECT409K1", "K409", "K-409", "NISTK409", "ANSIT409K1");
    }

    @Test
    public void b409() throws Exception {
        assertAliases(Curve.b409, "sect409r1", "b409", "nistb409", "ansit409r1", "SECT409R1", "B409", "B-409", "NISTB409", "ANSIT409R1");
    }

    @Test
    public void k571() throws Exception {
        assertAliases(Curve.k571, "sect571k1", "k571", "nistk571", "ansit571k1", "SECT571K1", "K571", "K-571", "NISTK571", "ANSIT571K1");
    }

    @Test
    public void b571() throws Exception {
        assertAliases(Curve.b571, "sect571r1", "b571", "nistb571", "ansit571r1", "SECT571R1", "B571", "B-571", "NISTB571", "ANSIT571R1");
    }

    @Test
    public void nistp192() throws Exception {
        assertAliases(Curve.nistp192, "secp192r1", "p192", "nistp192", "prime192v1", "SECP192R1", "P192", "P-192", "NISTP192", "PRIME192V1");
    }

    @Test
    public void nistp224() throws Exception {
        assertAliases(Curve.nistp224, "secp224r1", "p224", "nistp224", "ansip224r1", "SECP224R1", "P224", "P-224", "NISTP224", "ANSIP224R1");
    }

    @Test
    public void nistp256() throws Exception {
        assertAliases(Curve.nistp256, "secp256r1", "p256", "nistp256", "prime256v1", "SECP256R1", "P256", "P-256", "NISTP256", "PRIME256V1");
    }

    @Test
    public void nistp384() throws Exception {
        assertAliases(Curve.nistp384, "secp384r1", "p384", "nistp384", "ansip384r1", "SECP384R1", "P384", "P-384", "NISTP384", "ANSIP384R1");
    }

    @Test
    public void nistp521() throws Exception {
        assertAliases(Curve.nistp521, "secp521r1", "p521", "nistp521", "ansip521r1", "SECP521R1", "P521", "P-521", "NISTP521", "ANSIP521R1");
    }

    @Test
    public void nistk163() throws Exception {
        assertAliases(Curve.nistk163, "sect163k1", "k163", "nistk163", "ansit163k1", "SECT163K1", "K163", "K-163", "NISTK163", "ANSIT163K1");
    }

    @Test
    public void nistb163() throws Exception {
        assertAliases(Curve.nistb163, "sect163r2", "b163", "nistb163", "ansit163r2", "SECT163R2", "B163", "B-163", "NISTB163", "ANSIT163R2");
    }

    @Test
    public void nistk233() throws Exception {
        assertAliases(Curve.nistk233, "sect233k1", "k233", "nistk233", "ansit233k1", "SECT233K1", "K233", "K-233", "NISTK233", "ANSIT233K1");
    }

    @Test
    public void nistb233() throws Exception {
        assertAliases(Curve.nistb233, "sect233r1", "b233", "nistb233", "ansit233r1", "SECT233R1", "B233", "B-233", "NISTB233", "ANSIT233R1");
    }

    @Test
    public void nistk283() throws Exception {
        assertAliases(Curve.nistk283, "sect283k1", "k283", "nistk283", "ansit283k1", "SECT283K1", "K283", "K-283", "NISTK283", "ANSIT283K1");
    }

    @Test
    public void nistb283() throws Exception {
        assertAliases(Curve.nistb283, "sect283r1", "b283", "nistb283", "ansit283r1", "SECT283R1", "B283", "B-283", "NISTB283", "ANSIT283R1");
    }

    @Test
    public void nistk409() throws Exception {
        assertAliases(Curve.nistk409, "sect409k1", "k409", "nistk409", "ansit409k1", "SECT409K1", "K409", "K-409", "NISTK409", "ANSIT409K1");
    }

    @Test
    public void nistb409() throws Exception {
        assertAliases(Curve.nistb409, "sect409r1", "b409", "nistb409", "ansit409r1", "SECT409R1", "B409", "B-409", "NISTB409", "ANSIT409R1");
    }

    @Test
    public void nistk571() throws Exception {
        assertAliases(Curve.nistk571, "sect571k1", "k571", "nistk571", "ansit571k1", "SECT571K1", "K571", "K-571", "NISTK571", "ANSIT571K1");
    }

    @Test
    public void nistb571() throws Exception {
        assertAliases(Curve.nistb571, "sect571r1", "b571", "nistb571", "ansit571r1", "SECT571R1", "B571", "B-571", "NISTB571", "ANSIT571R1");
    }

    @Test
    public void brainpoolp160r1() throws Exception {
        assertAliases(Curve.brainpoolp160r1, "brainpoolp160r1", "BRAINPOOLP160R1");
    }

    @Test
    public void brainpoolp160t1() throws Exception {
        assertAliases(Curve.brainpoolp160t1, "brainpoolp160t1", "BRAINPOOLP160T1");
    }

    @Test
    public void brainpoolp192r1() throws Exception {
        assertAliases(Curve.brainpoolp192r1, "brainpoolp192r1", "BRAINPOOLP192R1");
    }

    @Test
    public void brainpoolp192t1() throws Exception {
        assertAliases(Curve.brainpoolp192t1, "brainpoolp192t1", "BRAINPOOLP192T1");
    }

    @Test
    public void brainpoolp224r1() throws Exception {
        assertAliases(Curve.brainpoolp224r1, "brainpoolp224r1", "BRAINPOOLP224R1");
    }

    @Test
    public void brainpoolp224t1() throws Exception {
        assertAliases(Curve.brainpoolp224t1, "brainpoolp224t1", "BRAINPOOLP224T1");
    }

    @Test
    public void brainpoolp256r1() throws Exception {
        assertAliases(Curve.brainpoolp256r1, "brainpoolp256r1", "BRAINPOOLP256R1");
    }

    @Test
    public void brainpoolp256t1() throws Exception {
        assertAliases(Curve.brainpoolp256t1, "brainpoolp256t1", "BRAINPOOLP256T1");
    }

    @Test
    public void brainpoolp320r1() throws Exception {
        assertAliases(Curve.brainpoolp320r1, "brainpoolp320r1", "BRAINPOOLP320R1");
    }

    @Test
    public void brainpoolp320t1() throws Exception {
        assertAliases(Curve.brainpoolp320t1, "brainpoolp320t1", "BRAINPOOLP320T1");
    }

    @Test
    public void brainpoolp384r1() throws Exception {
        assertAliases(Curve.brainpoolp384r1, "brainpoolp384r1", "BRAINPOOLP384R1");
    }

    @Test
    public void brainpoolp384t1() throws Exception {
        assertAliases(Curve.brainpoolp384t1, "brainpoolp384t1", "BRAINPOOLP384T1");
    }

    @Test
    public void brainpoolp512r1() throws Exception {
        assertAliases(Curve.brainpoolp512r1, "brainpoolp512r1", "BRAINPOOLP512R1");
    }

    @Test
    public void brainpoolp512t1() throws Exception {
        assertAliases(Curve.brainpoolp512t1, "brainpoolp512t1", "BRAINPOOLP512T1");
    }

    @Test
    public void frp256v1() throws Exception {
        assertAliases(Curve.frp256v1, "frp256v1", "FRP256V1");
    }

    @Test
    public void prime192v1() throws Exception {
        assertAliases(Curve.prime192v1, "secp192r1", "p192", "nistp192", "prime192v1", "SECP192R1", "P192", "P-192", "NISTP192", "PRIME192V1");
    }

    @Test
    public void prime192v2() throws Exception {
        assertAliases(Curve.prime192v2, "prime192v2", "PRIME192V2");
    }

    @Test
    public void prime192v3() throws Exception {
        assertAliases(Curve.prime192v3, "prime192v3", "PRIME192V3");
    }

    @Test
    public void prime239v1() throws Exception {
        assertAliases(Curve.prime239v1, "prime239v1", "PRIME239V1");
    }

    @Test
    public void prime239v2() throws Exception {
        assertAliases(Curve.prime239v2, "prime239v2", "PRIME239V2");
    }

    @Test
    public void prime239v3() throws Exception {
        assertAliases(Curve.prime239v3, "prime239v3", "PRIME239V3");
    }

    @Test
    public void prime256v1() throws Exception {
        assertAliases(Curve.prime256v1, "secp256r1", "p256", "nistp256", "prime256v1", "SECP256R1", "P256", "P-256", "NISTP256", "PRIME256V1");
    }

    @Test
    public void c2pnb176w1() throws Exception {
        assertAliases(Curve.c2pnb176w1, "c2pnb176w1", "C2PNB176W1");
    }

    @Test
    public void c2pnb163v1() throws Exception {
        assertAliases(Curve.c2pnb163v1, "c2pnb163v1", "C2PNB163V1");
    }

    @Test
    public void c2pnb163v2() throws Exception {
        assertAliases(Curve.c2pnb163v2, "c2pnb163v2", "C2PNB163V2");
    }

    @Test
    public void c2pnb163v3() throws Exception {
        assertAliases(Curve.c2pnb163v3, "c2pnb163v3", "C2PNB163V3");
    }

    @Test
    public void c2pnb208w1() throws Exception {
        assertAliases(Curve.c2pnb208w1, "c2pnb208w1", "C2PNB208W1");
    }

    @Test
    public void c2tnb191v3() throws Exception {
        assertAliases(Curve.c2tnb191v3, "c2tnb191v3", "C2TNB191V3");
    }

    @Test
    public void c2tnb191v2() throws Exception {
        assertAliases(Curve.c2tnb191v2, "c2tnb191v2", "C2TNB191V2");
    }

    @Test
    public void c2tnb191v1() throws Exception {
        assertAliases(Curve.c2tnb191v1, "c2tnb191v1", "C2TNB191V1");
    }

    @Test
    public void c2tnb239v3() throws Exception {
        assertAliases(Curve.c2tnb239v3, "c2tnb239v3", "C2TNB239V3");
    }

    @Test
    public void c2tnb239v2() throws Exception {
        assertAliases(Curve.c2tnb239v2, "c2tnb239v2", "C2TNB239V2");
    }

    @Test
    public void c2tnb239v1() throws Exception {
        assertAliases(Curve.c2tnb239v1, "c2tnb239v1", "C2TNB239V1");
    }

    @Test
    public void c2pnb272w1() throws Exception {
        assertAliases(Curve.c2pnb272w1, "c2pnb272w1", "C2PNB272W1");
    }

    @Test
    public void c2pnb304w1() throws Exception {
        assertAliases(Curve.c2pnb304w1, "c2pnb304w1", "C2PNB304W1");
    }

    @Test
    public void c2pnb368w1() throws Exception {
        assertAliases(Curve.c2pnb368w1, "c2pnb368w1", "C2PNB368W1");
    }

    @Test
    public void c2tnb359v1() throws Exception {
        assertAliases(Curve.c2tnb359v1, "c2tnb359v1", "C2TNB359V1");
    }

    @Test
    public void c2tnb431r1() throws Exception {
        assertAliases(Curve.c2tnb431r1, "c2tnb431r1", "C2TNB431R1");
    }

    @Test
    public void ansit163k1() throws Exception {
        assertAliases(Curve.ansit163k1, "sect163k1", "k163", "nistk163", "ansit163k1", "SECT163K1", "K163", "K-163", "NISTK163", "ANSIT163K1");
    }

    @Test
    public void ansit163r1() throws Exception {
        assertAliases(Curve.ansit163r1, "sect163r1", "ansit163r1", "SECT163R1", "ANSIT163R1");
    }

    @Test
    public void ansit163r2() throws Exception {
        assertAliases(Curve.ansit163r2, "sect163r2", "b163", "nistb163", "ansit163r2", "SECT163R2", "B163", "B-163", "NISTB163", "ANSIT163R2");
    }

    @Test
    public void ansit193r1() throws Exception {
        assertAliases(Curve.ansit193r1, "sect193r1", "ansit193r1", "SECT193R1", "ANSIT193R1");
    }

    @Test
    public void ansit193r2() throws Exception {
        assertAliases(Curve.ansit193r2, "sect193r2", "ansit193r2", "SECT193R2", "ANSIT193R2");
    }

    @Test
    public void ansit233k1() throws Exception {
        assertAliases(Curve.ansit233k1, "sect233k1", "k233", "nistk233", "ansit233k1", "SECT233K1", "K233", "K-233", "NISTK233", "ANSIT233K1");
    }

    @Test
    public void ansit233r1() throws Exception {
        assertAliases(Curve.ansit233r1, "sect233r1", "b233", "nistb233", "ansit233r1", "SECT233R1", "B233", "B-233", "NISTB233", "ANSIT233R1");
    }

    @Test
    public void ansit239k1() throws Exception {
        assertAliases(Curve.ansit239k1, "sect239k1", "ansit239k1", "SECT239K1", "ANSIT239K1");
    }

    @Test
    public void ansit283k1() throws Exception {
        assertAliases(Curve.ansit283k1, "sect283k1", "k283", "nistk283", "ansit283k1", "SECT283K1", "K283", "K-283", "NISTK283", "ANSIT283K1");
    }

    @Test
    public void ansit283r1() throws Exception {
        assertAliases(Curve.ansit283r1, "sect283r1", "b283", "nistb283", "ansit283r1", "SECT283R1", "B283", "B-283", "NISTB283", "ANSIT283R1");
    }

    @Test
    public void ansit409k1() throws Exception {
        assertAliases(Curve.ansit409k1, "sect409k1", "k409", "nistk409", "ansit409k1", "SECT409K1", "K409", "K-409", "NISTK409", "ANSIT409K1");
    }

    @Test
    public void ansit409r1() throws Exception {
        assertAliases(Curve.ansit409r1, "sect409r1", "b409", "nistb409", "ansit409r1", "SECT409R1", "B409", "B-409", "NISTB409", "ANSIT409R1");
    }

    @Test
    public void ansit571k1() throws Exception {
        assertAliases(Curve.ansit571k1, "sect571k1", "k571", "nistk571", "ansit571k1", "SECT571K1", "K571", "K-571", "NISTK571", "ANSIT571K1");
    }

    @Test
    public void ansit571r1() throws Exception {
        assertAliases(Curve.ansit571r1, "sect571r1", "b571", "nistb571", "ansit571r1", "SECT571R1", "B571", "B-571", "NISTB571", "ANSIT571R1");
    }

    @Test
    public void ansip160k1() throws Exception {
        assertAliases(Curve.ansip160k1, "secp160k1", "ansip160k1", "SECP160K1", "ANSIP160K1");
    }

    @Test
    public void ansip160r1() throws Exception {
        assertAliases(Curve.ansip160r1, "secp160r1", "ansip160r1", "SECP160R1", "ANSIP160R1");
    }

    @Test
    public void ansip160r2() throws Exception {
        assertAliases(Curve.ansip160r2, "secp160r2", "ansip160r2", "SECP160R2", "ANSIP160R2");
    }

    @Test
    public void ansip192k1() throws Exception {
        assertAliases(Curve.ansip192k1, "secp192k1", "ansip192k1", "SECP192K1", "ANSIP192K1");
    }

    @Test
    public void ansip224k1() throws Exception {
        assertAliases(Curve.ansip224k1, "secp224k1", "ansip224k1", "SECP224K1", "ANSIP224K1");
    }

    @Test
    public void ansip224r1() throws Exception {
        assertAliases(Curve.ansip224r1, "secp224r1", "p224", "nistp224", "ansip224r1", "SECP224R1", "P224", "P-224", "NISTP224", "ANSIP224R1");
    }

    @Test
    public void ansip256k1() throws Exception {
        assertAliases(Curve.ansip256k1, "secp256k1", "ansip256k1", "SECP256K1", "ANSIP256K1");
    }

    @Test
    public void ansip384r1() throws Exception {
        assertAliases(Curve.ansip384r1, "secp384r1", "p384", "nistp384", "ansip384r1", "SECP384R1", "P384", "P-384", "NISTP384", "ANSIP384R1");
    }

    @Test
    public void ansip521r1() throws Exception {
        assertAliases(Curve.ansip521r1, "secp521r1", "p521", "nistp521", "ansip521r1", "SECP521R1", "P521", "P-521", "NISTP521", "ANSIP521R1");
    }

    private void assertAliases(final Curve expected, final String... aliases) {
        for (final String alias : aliases) {
            final Curve actual = Curve.resolve(alias);
            CurveAsserts.assertParamSpec(expected.getParameterSpec(), actual.getParameterSpec());
        }
    }

    public static class Generate {
        public static void main(String[] args) {

            for (final Curve curve : Curve.values()) {
                //            if (!curve.name().startsWith("p")) continue;
                final Predicate<Curve> isAlias = other -> isAlias(curve, other);

                final List<String> aliases = Stream.of(Curve.values())
                        .filter(isAlias)
                        .map(Curve::name)
                        .map(s -> String.format("\"%s\"", s))
                        .collect(Collectors.toList());

                for (final String alias : new ArrayList<>(aliases)) {
                    final String upperCase = alias.toUpperCase();
                    aliases.add(upperCase);

                    final String s = upperCase.replaceAll("^\"([PBK])([0-9]{3})\"$", "\"$1-$2\"");
                    if (!s.equals(upperCase)) {
                        aliases.add(s);
                    }
                }

                System.out.printf("    @Test\n" +
                        "    public void %s() throws Exception {\n" +
                        "        assertAliases(Curve.%s, %s);\n" +
                        "    }\n" +
                        "\n", curve.name(), curve.name(), Join.join(", ", aliases));
            }
        }

        private static boolean isAlias(final Curve curve, final Curve other) {
            try {
                CurveAsserts.assertParamSpec(curve.getParameterSpec(), other.getParameterSpec());
                return true;
            } catch (Throwable ignored) {
                return false;
            }
        }
    }

}
