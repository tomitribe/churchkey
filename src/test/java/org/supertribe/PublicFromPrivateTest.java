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

import org.junit.Test;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;

import static org.junit.Assert.assertEquals;

public class PublicFromPrivateTest {

    @Test
    public void convert() throws Exception {

        final String pemFile = "" +
                "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIDV2ischPSu7JmDEhNlW9KpUiYl3AAANcMxRIEAxqk6hoAoGCCqGSM49\n" +
                "AwEHoUQDQgAERUSiTdfyjPPvepCpRGirABPcUo8QBaMJHoRf4D3XWBryDRMCZU20\n" +
                "GPXomXCQbIxJZtkOULn918lHK/CvytRW9A==\n" +
                "-----END EC PRIVATE KEY-----\n";

        // Read the PEM file
        final Key key = Keys.decode(pemFile.getBytes());

        // Get the public key
        final Key publicKey = key.getPublicKey();

        // Write the public key as PEM (or any other format)
        final byte[] encoded = publicKey.encode(Key.Format.PEM);

        assertEquals("" +
                "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERUSiTdfyjPPvepCpRGirABPcUo8Q\n" +
                "BaMJHoRf4D3XWBryDRMCZU20GPXomXCQbIxJZtkOULn918lHK/CvytRW9A==\n" +
                "-----END PUBLIC KEY-----\n", new String(encoded));
    }
}
