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

import java.security.spec.ECParameterSpec;

import static org.tomitribe.churchkey.ec.CurveAsserts.assertParamSpec;

/**
 * Tests our ability to support all the curves found
 * in OpenSSL 
 */
public class OpenSslEcCurvesTest {


    private final Resource resource = Resource.resource(this.getClass());

    @Test
    public void c2tnb191v1() throws Exception {
//        final String curveName = "c2pnb163v1";
        final String curveName = "c2tnb191v1";
        final byte[] bytes = resource.bytes(curveName + "-params.pem");
        final byte[] data = Pem.parse(bytes).getData();

        final ECParameterSpec spec = EcCurveParams.parse(data);
        assertParamSpec(Curve.c2tnb191v1.getParameterSpec(), spec);
    }

}
