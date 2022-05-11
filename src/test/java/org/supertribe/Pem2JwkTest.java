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
package org.supertribe;

import org.junit.Assert;
import org.junit.Test;
import io.churchkey.JsonAsserts;
import io.churchkey.Key;
import io.churchkey.Keys;

import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertEquals;

public class Pem2JwkTest {

    @Test
    public void convert() throws Exception {

        final String pemFile = "" +
                "-----BEGIN PUBLIC KEY-----\n" +
                "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyzNurU19lqnYhx5QI72sIX1lh\n" +
                "8cTehTmboC+DLG7UuaUHqs096M754HtP2IiHFcIQqwYNzHgKmjmfGdbk9JBkz/DN\n" +
                "eDVsA5nc7qTnsSgULXTxwHSF286IJdco5kasaJm4Xurlm3V+2oiTugraBsi1J0Ht\n" +
                "0OtHgJIlIaGxK7mY/QIDAQAB\n" +
                "-----END PUBLIC KEY-----\n";

        final Key key = Keys.decode(pemFile.getBytes());

        // We have a key instance we can use with JCE
        Assert.assertTrue(key.getKey() instanceof RSAPublicKey);

        // Write the key out to another format we need to use
        final byte[] jwkBytes = key.encode(Key.Format.JWK);

        final String jwk = new String(jwkBytes);
        final String expected = "" +
                "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"n\": \"sszbq1NfZap2IceUCO9rCF9ZYfHE3oU5m6Avgyxu1LmlB6rNPejO-eB7T9i" +
                "IhxXCEKsGDcx4Cpo5nxnW5PSQZM_wzXg1bAOZ3O6k57EoFC108cB0hdvOiCXXKOZGrGiZu" +
                "F7q5Zt1ftqIk7oK2gbItSdB7dDrR4CSJSGhsSu5mP0\"\n" +
                "}\n";

        JsonAsserts.assertJson(expected, jwk);
    }
}
