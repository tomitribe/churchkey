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

import java.security.spec.ECParameterSpec;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.tomitribe.churchkey.asn1.Asn1Dump.dump;
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

        final Oid oid = (Oid) BeginEcParameters.decode(bytes);
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

        EcCurveParams.name.set(openSslCurveName);
        final ECParameterSpec spec = (ECParameterSpec) BeginEcParameters.decode(bytes);
        assertParamSpec(curve.getParameterSpec(), spec);
    }

    /**
     * Ensure that the Curve parameters can be encoded
     * into something identical to what OpenSSL creates
     */
    @Test
    @Skip({
            /* This curve is wrong in OpenSSL/LibreSSL */
            "wap-wsg-idm-ecid-wtls7",
            /* For these 6 specs OpenSSL/LibreSSL will add padding
             * to both the x and y, where in the majority of other
             * cases the padding is trimmed.  We elect to consistently
             * trim x and y */
            "sect113r1",
            "wap-wsg-idm-ecid-wtls4",
            "wap-wsg-idm-ecid-wtls8",
            "wap-wsg-idm-ecid-wtls9",
            "Oakley-EC2N-3",
            "Oakley-EC2N-4",
            /* The curve wap-wsg-idm-ecid-wtls12 is an alias for secp224r1.
             * Despite them being identical, OpenSSL/LibreSSL will print
             * the seed for secp224r1 but not wap-wsg-idm-ecid-wtls12.
             * We chose not to replicate this inconsistency.
             */
            "wap-wsg-idm-ecid-wtls12",
    })
    public void encodeParameters() throws Exception {
        final byte[] expected = resource.bytes(openSslCurveName + "-params.pem");
        final byte[] actual = BeginEcParameters.encode(curve.getParameterSpec());

        assertEquals(dump(expected), dump(actual));
        assertEquals(new String(expected), new String(actual));
    }

    /**
     * Ensure that the Curve Oid can be encoded
     * into something identical to what OpenSSL creates
     */
//    @Test
    public void encodeOid() throws Exception {
        final byte[] bytes = resource.bytes(openSslCurveName + "-params.pem");

        final ECParameterSpec spec = (ECParameterSpec) BeginEcParameters.decode(bytes);
        assertParamSpec(curve.getParameterSpec(), spec);
    }


    @Parameters(name = "{0}")
    public static List<Object[]> params() {
        return OpenSslCurves.curves();
    }

}
