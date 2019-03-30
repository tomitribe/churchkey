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
package org.tomitribe.churchkey.jwk;

import org.junit.Test;
import org.tomitribe.churchkey.Decoder;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;
import org.tomitribe.churchkey.Resource;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class JwkRsaPrivateKeyEncodeTest {

    @Test
    public void testKeysDecode1024() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("rsa", 1024, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final Key key = decoder.decode(resource.bytes("private.jwk"));
        assertKey(expected, key);

        final byte[] encode = Keys.encode(key);

        assertEquals("{" +
                "\"n\":\"ALLM26tTX2WqdiHHlAjvawhfWWHxxN6FOZugL4MsbtS5pQeqzT3oz" +
                "vnge0_YiIcVwhCrBg3MeAqaOZ8Z1uT0kGTP8M14NWwDmdzupOexKBQtdPHAdI" +
                "Xbzogl1yjmRqxombhe6uWbdX7aiJO6CtoGyLUnQe3Q60eAkiUhobEruZj9\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"VWV8gV5nkMISe927eW0IHM6VfS8gzPqqYgbmymq9YIJuLLRKJIh92" +
                "mB55M_RnVsp_hYA5TREHSQ94xxPQ7j_ASohev1Etv7Hr9AFixa7Q6sRdT1DY7" +
                "YO1kf_wLk0Urg2bHrvAvukcmBAV9-OHKDkRUY-e03ZK3cCfetsHP41RmE\"," +
                "\"p\":\"AOlI_bS_DwfvJw7HIZASVI4xXQaRvwoHsCycKA2HPFkmxlJcPbooG" +
                "RlzR8OV0hvySPVdE_R8H3j68qtdRsoOnyU\"," +
                "\"q\":\"AMQ1vjCNOGuim9YGQ_rndD60rlgMM6QT_49AUEMBJUlm2g7iVybEr" +
                "tdU2AXh2K1qrxNhouwgCqzMvDMJ2EaDNvk\"," +
                "\"dp\":\"EcJBtgm5XjRBd-mGz43lq_FsEHz12xCcw7ibf_QkjvDZthlZhZtZ" +
                "1csl0mjMVt5J2YvdYgY06yPHZ24xXl5glQ\"," +
                "\"dq\":\"AMNnkoXf3rSzOOepTcJvB4H7hzYA0N0zXWxY7JYOagfz-m6gU5M0" +
                "hbvFr24MQjJS8REoR41JS9hT_YoG3_E5dGE\"," +
                "\"qi\":\"AMk2trEKy0AhZC7nN2YvtMSB8g_qIW9Vgy4k9PB9XUj38fmOZfKT" +
                "Z_3xuzeRlhYnPmnuYfhim19eHuDABOX2ICg\"," +
                "\"kty\":\"RSA\"" +
                "}", new String(encode));

        assertKey(expected, Keys.decode(encode));
    }

    public void assertKey(final RSAPrivateCrtKey expected, final Key key) {
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());

        final RSAPrivateCrtKey actual = (RSAPrivateCrtKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getModulus(), actual.getModulus());
        assertEquals(expected.getPrivateExponent(), actual.getPrivateExponent());
        assertEquals(expected.getPrimeP(), actual.getPrimeP());
        assertEquals(expected.getPrimeQ(), actual.getPrimeQ());
        assertEquals(expected.getPrimeExponentP(), actual.getPrimeExponentP());
        assertEquals(expected.getPrimeExponentQ(), actual.getPrimeExponentQ());
        assertEquals(expected.getCrtCoefficient(), actual.getCrtCoefficient());
    }

    @Test
    public void testKeysDecode2048() throws Exception {
        final Decoder decoder = Keys::decode;
        final Resource resource = Resource.resource("rsa", 2048, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(resource.bytes("private.pkcs8.der")));

        final Key key = decoder.decode(resource.bytes("private.jwk"));
        assertKey(expected, key);

        final byte[] encode = Keys.encode(key);

        assertEquals("{\"n\":\"ANOONCbZoZcsLZDL0erUzLNFOnvSWuMV4-fqvo6FnU9sQh7fd" +
                "QpPfuQuVjmkU3KOAjxTAcaFD4tY5LVuXPjspJziAAl7uoK13sWqxUC47ERBPnZA" +
                "1azLu-X-xm_f5Qu5q1TO99dfMJzD9ruTDkCKFzqqgtctYGqCWi6fzo04iRgpuLs" +
                "c7m81DzeSAwBWk3yvkBK4bXBngQ8Fo74pBn1H1_llau-AzqIIC4hmweI7E_IlVx" +
                "JudyXKBGPJ1a9soK_dk7lNfsSwBorI0UmCVXu1dbaXURtQosgiJKoQxXxQRoRZ1" +
                "pbuICjIk9Ck6APRiXzrgs-u12RAIUGIs3F259bsWjk\"," +
                "\"e\":\"AQAB\"," +
                "\"d\":\"AJvne0V6Mtx-YSIJIqzln-kpRn1Du1kIo8kgtMfBbfm-9UddNBqiFQh" +
                "BoaefEyQjxUABiBhtrNPrcbjHGVsUwgcfghl7BisXrpGLVQxqeyudzVNGWnGaPu" +
                "GzDTgbDufCL6IzWHBupRuSSv1W1TT4zz-bswqyVRCI-b7MZGKsXFPh6uUm3FHdI" +
                "-lJbecm3gO-65xO_g1Cd69rJPCxqZfNbD4fMaF5ucAYybaQ-D6uoreM7Am_FB3M" +
                "-KbOdr7YicrOq8ha4NihGUeMllX6Hgpy87h-xT6i3_PX9O-FJODqnaIvSXeOMDV" +
                "RTesshlmH_zvVZlPX7aKekOtaqb9ZJuEJ1RU\"," +
                "\"p\":\"AP7iQI1h0ePwtjpTEyA6o4hIKvUaKrWaQNLw2h_IYnkTiSE49wqU-CP" +
                "EJd-qG8y0rv1OzmjHtArAWyIcEkuKMFb-abRn8eo-CSrU0JZ1atA8aGq_scCAqE" +
                "WXdMDTS-sAHH2SThAhHCfEUssU7dNdjqWvATb3otJYLK-mw5H6LRGP\"," +
                "\"q\":\"ANR7YGhc-lCmCzOUiwGvehbA4D3Hzy9swrb30Lhs2IAxZsQJB0wXGTb" +
                "Oa-tzBbpCv7T6QH5U1gAmDYzhSlp47gXGIPUlQGin6HA-h_IxZUUkmR-76jOPIm" +
                "36WTVIHt-HCI_AktAB5gWQpXNY9kUUMO_4QqH-4bgrhzrDe1LMLeO3\"," +
                "\"dp\":\"CQjWBuzntq-qleip7eOGNmdwdl2mE-fS0mdNJAFDVE1X-AB_6TUcko" +
                "_6U7JA6AGjjkED2fzyKctlr5DVKS5NxlegQY_JqGbohkci2aJx1c2-WcJPt6YX0" +
                "NesgMU8lKjdWaoc8D9sMxCnaqFkSLCxRLguT9d5QwFzHArKNdtrS4s\"," +
                "\"dq\":\"Uim7J9_8Mz9hyXpBHk-6iB3hGEKxTQdja9j77rS4KynvMRLErZmo-F" +
                "ZtyMfbiSDSfKrgUXmAnuIYD0f2tnFYqQbqK6FR_KYg7XZgnziWjlwOkgTaFUHd8" +
                "GUEJeRTe9_9YYj3vFNfnPtH3wihgijCm6iGK5ohslOyoPiCMYwempU\"," +
                "\"qi\":\"AO2qP3nA8eeyUqD_ZJkVrxBpVlEnG6Cb8dgKnsoBnw6OBMqT0UnMet" +
                "p4uKyv7RXtqfJGwNMERenvRdd8i5Hjp7cRVL1Zta0_u8ukbodRNa2afYQFK674D" +
                "QGMXv0K4g--7tDybHASN7O9Sif4eN1Q_h4HF0cw9T1gjfVg0P9US8-f\"," +
                "\"kty\":\"RSA\"" +
                "}", new String(encode));

        assertKey(expected, Keys.decode(encode));
    }

}