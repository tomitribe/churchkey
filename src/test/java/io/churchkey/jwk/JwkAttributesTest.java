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

import io.churchkey.Key;
import io.churchkey.Keys;
import org.junit.Test;

public class JwkAttributesTest extends org.junit.Assert {

    @Test
    public void privateKeyAttributesRsa() throws Exception {
        final String jwk = "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"kid\": \"1234\",\n" +
                "  \"objects\": {\"feet\":5},\n" +
                "  \"numbers\": 6,\n" +
                "  \"booleans\": true,\n" +
                "  \"arrays\": [true],\n" +
                "  \"nulls\": null,\n" +
                "  \"n\": \"sszbq1NfZap2IceUCO9rCF9ZYfHE3oU5m6Avgyxu1LmlB6rNPejO-eB7T9iIhxXCEKsGDcx4Cpo5nxnW5PSQZM_" +
                "wzXg1bAOZ3O6k57EoFC108cB0hdvOiCXXKOZGrGiZuF7q5Zt1ftqIk7oK2gbItSdB7dDrR4CSJSGhsSu5mP0\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"d\": \"VWV8gV5nkMISe927eW0IHM6VfS8gzPqqYgbmymq9YIJuLLRKJIh92mB55M_RnVsp_hYA5TREHSQ94xxPQ7j_ASohev1Etv7Hr9AFixa7Q6sRdT1DY7Y" +
                "O1kf_wLk0Urg2bHrvAvukcmBAV9-OHKDkRUY-e03ZK3cCfetsHP41RmE\",\n" +
                "  \"p\": \"6Uj9tL8PB-8nDschkBJUjjFdBpG_CgewLJwoDYc8WSbGUlw9uigZGXNHw5XSG_JI9V0T9HwfePryq11Gyg6fJQ\",\n" +
                "  \"q\": \"xDW-MI04a6Kb1gZD-ud0PrSuWAwzpBP_j0BQQwElSWbaDuJXJsSu11TYBeHYrWqvE2Gi7CAKrMy8MwnYRoM2-Q\",\n" +
                "  \"dp\": \"EcJBtgm5XjRBd-mGz43lq_FsEHz12xCcw7ibf_QkjvDZthlZhZtZ1csl0mjMVt5J2YvdYgY06yPHZ24xXl5glQ\",\n" +
                "  \"dq\": \"w2eShd_etLM456lNwm8HgfuHNgDQ3TNdbFjslg5qB_P6bqBTkzSFu8WvbgxCMlLxEShHjUlL2FP9igbf8Tl0YQ\",\n" +
                "  \"qi\": \"yTa2sQrLQCFkLuc3Zi-0xIHyD-ohb1WDLiT08H1dSPfx-Y5l8pNn_fG7N5GWFic-ae5h-GKbX14e4MAE5fYgKA\"\n" +
                "}";

        final Key key = Keys.decode(jwk.getBytes());

        assertEquals("1234", key.getAttribute("kid"));
        assertEquals("{\"feet\":5}", key.getAttribute("objects"));
        assertEquals("6", key.getAttribute("numbers"));
        assertEquals(null, key.getAttribute("nulls"));
        assertEquals("[true]", key.getAttribute("arrays"));

        assertTrue(!key.getAttributes().containsKey("kty"));
        assertTrue(!key.getAttributes().containsKey("n"));
        assertTrue(!key.getAttributes().containsKey("e"));
        assertTrue(!key.getAttributes().containsKey("d"));
        assertTrue(!key.getAttributes().containsKey("p"));
        assertTrue(!key.getAttributes().containsKey("q"));
        assertTrue(!key.getAttributes().containsKey("dp"));
        assertTrue(!key.getAttributes().containsKey("dq"));
        assertTrue(!key.getAttributes().containsKey("qi"));

        assertEquals(6, key.getAttributes().size());
    }

    @Test
    public void publicKeyAttributesRsa() throws Exception {
        final String jwk = "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"kid\": \"1234\",\n" +
                "  \"objects\": {\"feet\":5},\n" +
                "  \"numbers\": 6,\n" +
                "  \"booleans\": true,\n" +
                "  \"arrays\": [true],\n" +
                "  \"nulls\": null,\n" +
                "  \"n\": \"sszbq1NfZap2IceUCO9rCF9ZYfHE3oU5m6Avgyxu1LmlB6rNPejO-eB7T9iIhxXCEKsGDcx4Cpo5nxnW5PSQZM_" +
                "wzXg1bAOZ3O6k57EoFC108cB0hdvOiCXXKOZGrGiZuF7q5Zt1ftqIk7oK2gbItSdB7dDrR4CSJSGhsSu5mP0\",\n" +
                "  \"e\": \"AQAB\"\n" +
                "}";

        final Key key = Keys.decode(jwk.getBytes());

        assertEquals("1234", key.getAttribute("kid"));
        assertEquals("{\"feet\":5}", key.getAttribute("objects"));
        assertEquals("6", key.getAttribute("numbers"));
        assertEquals(null, key.getAttribute("nulls"));
        assertEquals("[true]", key.getAttribute("arrays"));

        assertTrue(!key.getAttributes().containsKey("kty"));
        assertTrue(!key.getAttributes().containsKey("n"));
        assertTrue(!key.getAttributes().containsKey("e"));
        assertTrue(!key.getAttributes().containsKey("d"));
        assertTrue(!key.getAttributes().containsKey("p"));
        assertTrue(!key.getAttributes().containsKey("q"));
        assertTrue(!key.getAttributes().containsKey("dp"));
        assertTrue(!key.getAttributes().containsKey("dq"));
        assertTrue(!key.getAttributes().containsKey("qi"));

        assertEquals(6, key.getAttributes().size());
    }
}