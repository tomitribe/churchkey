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

import org.junit.Test;
import org.tomitribe.churchkey.Resource;
import org.tomitribe.churchkey.ec.Curve;
import org.tomitribe.churchkey.util.Pem;

import java.io.IOException;
import java.security.spec.ECParameterSpec;

import static org.tomitribe.churchkey.ec.CurveAsserts.assertParamSpec;

/**
 * Tests our ability to support all the curves found
 * in OpenSSL 
 */
public class OpenSslEcCurvesTest {


    private final Resource resource = Resource.resource(this.getClass());

    @Test
    public void secp112r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp112r1", Curve.secp112r1);
    }

    @Test
    public void secp112r2ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp112r2", Curve.secp112r2);
    }

    @Test
    public void secp128r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp128r1", Curve.secp128r1);
    }

    @Test
    public void secp128r2ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp128r2", Curve.secp128r2);
    }

    @Test
    public void secp160k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp160k1", Curve.secp160k1);
    }

    @Test
    public void secp160r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp160r1", Curve.secp160r1);
    }

    @Test
    public void secp160r2ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp160r2", Curve.secp160r2);
    }

    @Test
    public void secp192k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp192k1", Curve.secp192k1);
    }

    @Test
    public void secp224k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp224k1", Curve.secp224k1);
    }

    @Test
    public void secp224r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp224r1", Curve.secp224r1);
    }

    @Test
    public void secp256k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp256k1", Curve.secp256k1);
    }

    @Test
    public void secp384r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp384r1", Curve.secp384r1);
    }

    @Test
    public void secp521r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("secp521r1", Curve.secp521r1);
    }

    @Test
    public void prime192v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("prime192v1", Curve.prime192v1);
    }

    @Test
    public void prime192v2ParameterSpec() throws Exception {
        assertCurveParameterSpec("prime192v2", Curve.prime192v2);
    }

    @Test
    public void prime192v3ParameterSpec() throws Exception {
        assertCurveParameterSpec("prime192v3", Curve.prime192v3);
    }

    @Test
    public void prime239v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("prime239v1", Curve.prime239v1);
    }

    @Test
    public void prime239v2ParameterSpec() throws Exception {
        assertCurveParameterSpec("prime239v2", Curve.prime239v2);
    }

    @Test
    public void prime239v3ParameterSpec() throws Exception {
        assertCurveParameterSpec("prime239v3", Curve.prime239v3);
    }

    @Test
    public void prime256v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("prime256v1", Curve.prime256v1);
    }

    @Test
    public void sect113r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect113r1", Curve.sect113r1);
    }

    @Test
    public void sect113r2ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect113r2", Curve.sect113r2);
    }

    @Test
    public void sect131r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect131r1", Curve.sect131r1);
    }

    @Test
    public void sect131r2ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect131r2", Curve.sect131r2);
    }

    @Test
    public void sect163k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect163k1", Curve.sect163k1);
    }

    @Test
    public void sect163r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect163r1", Curve.sect163r1);
    }

    @Test
    public void sect163r2ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect163r2", Curve.sect163r2);
    }

    @Test
    public void sect193r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect193r1", Curve.sect193r1);
    }

    @Test
    public void sect193r2ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect193r2", Curve.sect193r2);
    }

    @Test
    public void sect233k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect233k1", Curve.sect233k1);
    }

    @Test
    public void sect233r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect233r1", Curve.sect233r1);
    }

    @Test
    public void sect239k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect239k1", Curve.sect239k1);
    }

    @Test
    public void sect283k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect283k1", Curve.sect283k1);
    }

    @Test
    public void sect283r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect283r1", Curve.sect283r1);
    }

    @Test
    public void sect409k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect409k1", Curve.sect409k1);
    }

    @Test
    public void sect409r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect409r1", Curve.sect409r1);
    }

    @Test
    public void sect571k1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect571k1", Curve.sect571k1);
    }

    @Test
    public void sect571r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("sect571r1", Curve.sect571r1);
    }

    @Test
    public void c2pnb163v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2pnb163v1", Curve.c2pnb163v1);
    }

    @Test
    public void c2pnb163v2ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2pnb163v2", Curve.c2pnb163v2);
    }

    @Test
    public void c2pnb163v3ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2pnb163v3", Curve.c2pnb163v3);
    }

//    @Test
//    public void c2pnb176v1ParameterSpec() throws Exception {
//        assertCurveParameterSpec("c2pnb176v1", Curve.c2pnb176v1);
//    }

    @Test
    public void c2tnb191v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb191v1", Curve.c2tnb191v1);
    }

    @Test
    public void c2tnb191v2ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb191v2", Curve.c2tnb191v2);
    }

    @Test
    public void c2tnb191v3ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb191v3", Curve.c2tnb191v3);
    }

    @Test
    public void c2pnb208w1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2pnb208w1", Curve.c2pnb208w1);
    }

    @Test
    public void c2tnb239v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb239v1", Curve.c2tnb239v1);
    }

    @Test
    public void c2tnb239v2ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb239v2", Curve.c2tnb239v2);
    }

    @Test
    public void c2tnb239v3ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb239v3", Curve.c2tnb239v3);
    }

    @Test
    public void c2pnb272w1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2pnb272w1", Curve.c2pnb272w1);
    }

    @Test
    public void c2pnb304w1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2pnb304w1", Curve.c2pnb304w1);
    }

    @Test
    public void c2tnb359v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb359v1", Curve.c2tnb359v1);
    }

    @Test
    public void c2pnb368w1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2pnb368w1", Curve.c2pnb368w1);
    }

    @Test
    public void c2tnb431r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("c2tnb431r1", Curve.c2tnb431r1);
    }

//    @Test
//    public void wapwsgidmecidwtls1ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls1", Curve.wapwsgidmecidwtls1);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls3ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls3", Curve.wapwsgidmecidwtls3);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls4ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls4", Curve.wapwsgidmecidwtls4);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls5ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls5", Curve.wapwsgidmecidwtls5);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls6ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls6", Curve.wapwsgidmecidwtls6);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls7ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls7", Curve.wapwsgidmecidwtls7);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls8ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls8", Curve.wapwsgidmecidwtls8);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls9ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls9", Curve.wapwsgidmecidwtls9);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls10ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls10", Curve.wapwsgidmecidwtls10);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls11ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls11", Curve.wapwsgidmecidwtls11);
//    }
//
//    @Test
//    public void wapwsgidmecidwtls12ParameterSpec() throws Exception {
//        assertCurveParameterSpec("wap-wsg-idm-ecid-wtls12", Curve.wapwsgidmecidwtls12);
//    }
//
//    @Test
//    public void oakleyec2n3ParameterSpec() throws Exception {
//        assertCurveParameterSpec("Oakley-EC2N-3", Curve.oakleyec2n3);
//    }
//
//    @Test
//    public void oakleyec2n4ParameterSpec() throws Exception {
//        assertCurveParameterSpec("Oakley-EC2N-4", Curve.oakleyec2n4);
//    }
//
    @Test
    public void brainpoolp160r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP160r1", Curve.brainpoolp160r1);
    }

    @Test
    public void brainpoolp160t1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP160t1", Curve.brainpoolp160t1);
    }

    @Test
    public void brainpoolp192r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP192r1", Curve.brainpoolp192r1);
    }

    @Test
    public void brainpoolp192t1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP192t1", Curve.brainpoolp192t1);
    }

    @Test
    public void brainpoolp224r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP224r1", Curve.brainpoolp224r1);
    }

    @Test
    public void brainpoolp224t1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP224t1", Curve.brainpoolp224t1);
    }

    @Test
    public void brainpoolp256r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP256r1", Curve.brainpoolp256r1);
    }

    @Test
    public void brainpoolp256t1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP256t1", Curve.brainpoolp256t1);
    }

    @Test
    public void brainpoolp320r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP320r1", Curve.brainpoolp320r1);
    }

    @Test
    public void brainpoolp320t1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP320t1", Curve.brainpoolp320t1);
    }

    @Test
    public void brainpoolp384r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP384r1", Curve.brainpoolp384r1);
    }

    @Test
    public void brainpoolp384t1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP384t1", Curve.brainpoolp384t1);
    }

    @Test
    public void brainpoolp512r1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP512r1", Curve.brainpoolp512r1);
    }

    @Test
    public void brainpoolp512t1ParameterSpec() throws Exception {
        assertCurveParameterSpec("brainpoolP512t1", Curve.brainpoolp512t1);
    }

    @Test
    public void frp256v1ParameterSpec() throws Exception {
        assertCurveParameterSpec("FRP256v1", Curve.frp256v1);
    }

//    @Test
//    public void idgostr34102001testparamsetParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-GostR3410-2001-TestParamSet", Curve.idgostr34102001testparamset);
//    }
//
//    @Test
//    public void idgostr34102001cryptoproaparamsetParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-GostR3410-2001-CryptoPro-A-ParamSet", Curve.idgostr34102001cryptoproaparamset);
//    }
//
//    @Test
//    public void idgostr34102001cryptoprobparamsetParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-GostR3410-2001-CryptoPro-B-ParamSet", Curve.idgostr34102001cryptoprobparamset);
//    }
//
//    @Test
//    public void idgostr34102001cryptoprocparamsetParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-GostR3410-2001-CryptoPro-C-ParamSet", Curve.idgostr34102001cryptoprocparamset);
//    }
//
//    @Test
//    public void idgostr34102001cryptoproxchaparamsetParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-GostR3410-2001-CryptoPro-XchA-ParamSet", Curve.idgostr34102001cryptoproxchaparamset);
//    }
//
//    @Test
//    public void idgostr34102001cryptoproxchbparamsetParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-GostR3410-2001-CryptoPro-XchB-ParamSet", Curve.idgostr34102001cryptoproxchbparamset);
//    }
//
//    @Test
//    public void idtc26gost34102012512paramsetaParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-tc26-gost-3410-2012-512-paramSetA", Curve.idtc26gost34102012512paramseta);
//    }
//
//    @Test
//    public void idtc26gost34102012512paramsetbParameterSpec() throws Exception {
//        assertCurveParameterSpec("id-tc26-gost-3410-2012-512-paramSetB", Curve.idtc26gost34102012512paramsetb);
//    }
//

    private void assertCurveParameterSpec(final String curveName, final Curve curve) throws IOException {
        final byte[] bytes = resource.bytes(curveName + "-params.pem");
        final byte[] data = Pem.parse(bytes).getData();

        final ECParameterSpec spec = EcCurveParams.parse(data);
        assertParamSpec(curve.getParameterSpec(), spec);
    }

}
