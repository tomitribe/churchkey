/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.churchkey.jwk;

import org.junit.Test;
import io.churchkey.Key;

import java.util.Base64;

public class JwkSecretKeyTest extends org.junit.Assert {

    @Test
    public void testHs256SecretKey() throws Exception {
        final String jwk = "" +
                "{ \"kty\": \"oct\",\n" +
                "  \"use\": \"sig\",\n" +
                "  \"kid\": \"orange-1234\",\n" +
                "  \"k\": \"VZ-0QGLZ2P_RPUSW10CIu0WMyXq-ND2pmDYzA0OTKW" +
                "THlp5iac5K4VeiRr-_BOoXJ4X2fSTt4nHwo_quta7j" +
                "JJKT4PEWyYanBSFsi0DW7owT-HExAGDyJtHUtNw5xs" +
                "s8Nj6OxNPv6rROE-kevhL2wB9cqgdIscbvDhras39c" +
                "wfs\",\n" +
                "  \"alg\": \"HS256\"\n" +
                "}";

        final Key key = Key.decode(jwk.getBytes());

        assertEquals("orange-1234", key.getAttribute("kid"));
        assertEquals("sig", key.getAttribute("use"));
        assertEquals("HS256", key.getAttribute("alg"));

        assertTrue(!key.getAttributes().containsKey("kty"));
        assertTrue(!key.getAttributes().containsKey("k"));

        assertEquals(3, key.getAttributes().size());

        final String encoded = "VZ-0QGLZ2P_RPUSW10CIu0WMyXq-ND2" +
                "pmDYzA0OTKWTHlp5iac5K4VeiRr-_BOoXJ4X2fSTt4nHwo_" +
                "quta7jJJKT4PEWyYanBSFsi0DW7owT-HExAGDyJtHUtNw5x" +
                "ss8Nj6OxNPv6rROE-kevhL2wB9cqgdIscbvDhras39cwfs";

        assertArrayEquals(key.getKey().getEncoded(), Base64.getUrlDecoder().decode(encoded));
        assertEquals(key.getAlgorithm(), Key.Algorithm.OCT);
        assertEquals(key.getFormat(), Key.Format.JWK);
        assertEquals(key.getType(), Key.Type.SECRET);
    }

}