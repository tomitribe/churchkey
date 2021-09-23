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
package org.tomitribe.churchkey.pem;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.tomitribe.churchkey.Resource;
import org.tomitribe.churchkey.Skip;
import org.tomitribe.churchkey.asn1.Oid;
import org.tomitribe.churchkey.ec.Curve;
import org.tomitribe.churchkey.util.Pem;

import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.tomitribe.churchkey.ec.CurveAsserts.assertParamSpec;

/**
 * Tests our ability to support all the curves found
 * in OpenSSL 
 */
@RunWith(Parameterized.class)
public class OpenSslEcCurvesTest {

    @Rule
    public Skip.Rule skip = new Skip.Rule();

    private final Resource resource = Resource.resource(this.getClass());

    private final String openSslCurveName;
    private final Curve curve;

    public OpenSslEcCurvesTest(final String openSslCurveName, final Curve curve) {
        this.openSslCurveName = openSslCurveName;
        this.curve = curve;
    }

    /**
     * Oakley-EC2N-3 and Oakley-EC2N-4 are ignored because
     * they have no OID according to OpenSSL
     */
    @Test
    @Skip({"Oakley-EC2N-3", "Oakley-EC2N-4"})
    public void oid() throws Exception {
        final byte[] bytes = resource.bytes(openSslCurveName + "-oid.pem");
        final byte[] data = Pem.parse(bytes).getData();

        final Oid oid = EcCurveParams.parseOid(data);
        final Curve actual = Curve.resolve(oid);
        assertNotNull("OID could not be resolved " + oid, actual);
        if (!curve.equals(actual) && !curve.getAliases().contains(actual) && !actual.getAliases().contains(curve)) {
            fail("Expected: " + curve + ", found: " + actual);
        }
    }

    /**
     * wap-wsg-idm-ecid-wtls7 is ignored due to a bug in OpenSSL
     * https://github.com/openssl/openssl/issues/6317
     */
    @Test
    @Skip("wap-wsg-idm-ecid-wtls7")
    public void parameterSpec() throws Exception {
        final byte[] bytes = resource.bytes(openSslCurveName + "-params.pem");
        final byte[] data = Pem.parse(bytes).getData();

        final ECParameterSpec spec = EcCurveParams.parse(data);
        assertParamSpec(curve.getParameterSpec(), spec);
    }

    @Parameters(name = "{0}")
    public static List<Object[]> params() {
        return Arrays.asList(new Object[][]{
                        {"secp112r1", Curve.secp112r1},
                        {"secp112r2", Curve.secp112r2},
                        {"secp128r1", Curve.secp128r1},
                        {"secp128r2", Curve.secp128r2},
                        {"secp160k1", Curve.secp160k1},
                        {"secp160r1", Curve.secp160r1},
                        {"secp160r2", Curve.secp160r2},
                        {"secp192k1", Curve.secp192k1},
                        {"secp224k1", Curve.secp224k1},
                        {"secp224r1", Curve.secp224r1},
                        {"secp256k1", Curve.secp256k1},
                        {"secp384r1", Curve.secp384r1},
                        {"secp521r1", Curve.secp521r1},
                        {"prime192v1", Curve.prime192v1},
                        {"prime192v2", Curve.prime192v2},
                        {"prime192v3", Curve.prime192v3},
                        {"prime239v1", Curve.prime239v1},
                        {"prime239v2", Curve.prime239v2},
                        {"prime239v3", Curve.prime239v3},
                        {"prime256v1", Curve.prime256v1},
                        {"sect113r1", Curve.sect113r1},
                        {"sect113r2", Curve.sect113r2},
                        {"sect131r1", Curve.sect131r1},
                        {"sect131r2", Curve.sect131r2},
                        {"sect163k1", Curve.sect163k1},
                        {"sect163r1", Curve.sect163r1},
                        {"sect163r2", Curve.sect163r2},
                        {"sect193r1", Curve.sect193r1},
                        {"sect193r2", Curve.sect193r2},
                        {"sect233k1", Curve.sect233k1},
                        {"sect233r1", Curve.sect233r1},
                        {"sect239k1", Curve.sect239k1},
                        {"sect283k1", Curve.sect283k1},
                        {"sect283r1", Curve.sect283r1},
                        {"sect409k1", Curve.sect409k1},
                        {"sect409r1", Curve.sect409r1},
                        {"sect571k1", Curve.sect571k1},
                        {"sect571r1", Curve.sect571r1},
                        {"c2pnb163v1", Curve.c2pnb163v1},
                        {"c2pnb163v2", Curve.c2pnb163v2},
                        {"c2pnb163v3", Curve.c2pnb163v3},
                        {"c2pnb176v1", Curve.c2pnb176v1},
                        {"c2tnb191v1", Curve.c2tnb191v1},
                        {"c2tnb191v2", Curve.c2tnb191v2},
                        {"c2tnb191v3", Curve.c2tnb191v3},
                        {"c2pnb208w1", Curve.c2pnb208w1},
                        {"c2tnb239v1", Curve.c2tnb239v1},
                        {"c2tnb239v2", Curve.c2tnb239v2},
                        {"c2tnb239v3", Curve.c2tnb239v3},
                        {"c2pnb272w1", Curve.c2pnb272w1},
                        {"c2pnb304w1", Curve.c2pnb304w1},
                        {"c2tnb359v1", Curve.c2tnb359v1},
                        {"c2pnb368w1", Curve.c2pnb368w1},
                        {"c2tnb431r1", Curve.c2tnb431r1},
                        {"wap-wsg-idm-ecid-wtls1", Curve.wapwsgidmecidwtls1},
                        {"wap-wsg-idm-ecid-wtls3", Curve.wapwsgidmecidwtls3},
                        {"wap-wsg-idm-ecid-wtls4", Curve.wapwsgidmecidwtls4},
                        {"wap-wsg-idm-ecid-wtls5", Curve.wapwsgidmecidwtls5},
                        {"wap-wsg-idm-ecid-wtls6", Curve.wapwsgidmecidwtls6},
                        {"wap-wsg-idm-ecid-wtls7", Curve.wapwsgidmecidwtls7},
                        {"wap-wsg-idm-ecid-wtls8", Curve.wapwsgidmecidwtls8},
                        {"wap-wsg-idm-ecid-wtls9", Curve.wapwsgidmecidwtls9},
                        {"wap-wsg-idm-ecid-wtls10", Curve.wapwsgidmecidwtls10},
                        {"wap-wsg-idm-ecid-wtls11", Curve.wapwsgidmecidwtls11},
                        {"wap-wsg-idm-ecid-wtls12", Curve.wapwsgidmecidwtls12},
                        {"Oakley-EC2N-3", Curve.oakleyec2n3},
                        {"Oakley-EC2N-4", Curve.oakleyec2n4},
                        {"brainpoolP160r1", Curve.brainpoolp160r1},
                        {"brainpoolP160t1", Curve.brainpoolp160t1},
                        {"brainpoolP192r1", Curve.brainpoolp192r1},
                        {"brainpoolP192t1", Curve.brainpoolp192t1},
                        {"brainpoolP224r1", Curve.brainpoolp224r1},
                        {"brainpoolP224t1", Curve.brainpoolp224t1},
                        {"brainpoolP256r1", Curve.brainpoolp256r1},
                        {"brainpoolP256t1", Curve.brainpoolp256t1},
                        {"brainpoolP320r1", Curve.brainpoolp320r1},
                        {"brainpoolP320t1", Curve.brainpoolp320t1},
                        {"brainpoolP384r1", Curve.brainpoolp384r1},
                        {"brainpoolP384t1", Curve.brainpoolp384t1},
                        {"brainpoolP512r1", Curve.brainpoolp512r1},
                        {"brainpoolP512t1", Curve.brainpoolp512t1},
                        {"FRP256v1", Curve.frp256v1},
                        {"id-GostR3410-2001-TestParamSet", Curve.idgostr34102001testparamset},
                        {"id-GostR3410-2001-CryptoPro-A-ParamSet", Curve.idgostr34102001cryptoproaparamset},
                        {"id-GostR3410-2001-CryptoPro-B-ParamSet", Curve.idgostr34102001cryptoprobparamset},
                        {"id-GostR3410-2001-CryptoPro-C-ParamSet", Curve.idgostr34102001cryptoprocparamset},
                        {"id-GostR3410-2001-CryptoPro-XchA-ParamSet", Curve.idgostr34102001cryptoproxchaparamset},
                        {"id-GostR3410-2001-CryptoPro-XchB-ParamSet", Curve.idgostr34102001cryptoproxchbparamset},
                        {"id-tc26-gost-3410-2012-512-paramSetA", Curve.idtc26gost34102012512paramseta},
                        {"id-tc26-gost-3410-2012-512-paramSetB", Curve.idtc26gost34102012512paramsetb},
                }
        );
    }
}
