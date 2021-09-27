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

import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Resource;
import org.tomitribe.churchkey.Skip;
import org.tomitribe.churchkey.ec.Curve;
import org.tomitribe.util.Hex;

import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class BeginEcPrivateKeyTest {

    @Rule
    public Skip.Rule skip = new Skip.Rule();

    private final Resource resource = Resource.resource(this.getClass());

    @Parameterized.Parameters(name = "{0}")
    public static List<Object[]> params() {
        return OpenSslCurves.curves();
    }

    private final String openSslCurveName;
    private final Curve curve;

    public BeginEcPrivateKeyTest(final String openSslCurveName, final Curve curve) {
        this.openSslCurveName = openSslCurveName;
        this.curve = curve;
    }


    /**
     * Oakley-EC2N-3 and Oakley-EC2N-4 are ignored because
     * they have no OID according to OpenSSL
     */
    @Test
    @Skip({"Oakley-EC2N-3", "Oakley-EC2N-4"})
    public void decodeOidFormat() throws Exception {
        assertDecode("oid");
    }

    /**
     * wap-wsg-idm-ecid-wtls7 is ignored due to a bug in OpenSSL
     * https://github.com/openssl/openssl/issues/6317
     */
    @Test
    @Skip("wap-wsg-idm-ecid-wtls7")
    public void decodeParameterFormat() throws Exception {
        assertDecode("params");
    }

    private void assertDecode(final String format) throws IOException {
        final byte[] bytes = resource.bytes("private.pkcs1." + openSslCurveName + "." + format + ".pem");
        final Key key = EcKeys.decode(bytes);

        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Type.PRIVATE, key.getType());
        final ECPrivateKey privateKey = (ECPrivateKey) key.getKey();

        { // assert private key integer
            final byte[] expected = resource.bytes("private.pkcs1." + openSslCurveName + "." + format + ".txt");
            assertEquals(new String(expected), Hex.toString(privateKey.getS().toByteArray()));
        }

        { // assert curve parameters
            final ECParameterSpec params = privateKey.getParams();
            assertTrue(curve.isEqual(params));
        }
    }

    //    @Test
    @Ignore
    public void encode() throws Exception {

    }

}
