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
package io.churchkey;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;
import org.junit.Ignore;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static io.churchkey.Key.Format.JWK;
import static io.churchkey.Key.Format.OPENSSH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * Intentionally simplistic test for the purposes of tracking
 * which encoding scenarios are implemented and which are not.
 *
 * More exhaustive tests for each scenario are elsewhere.
 */
public class KeyEncodeSetTest {

    private final Resource resource = Resource.resource(this.getClass());

    @Test
    public void rsaPublicPemPkcs1() throws Exception {
        assertEncoding("rsaPublicPemPkcs1.pem", Key.Format.PEM, "" +
                "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+xGZ/wcz9ugFpP07Nspo\n" +
                "6U17l0YhFiFpxxU4pTk3Lifz9R3zsIsuERwta7+fWIfxOo208ett/jhskiVodSEt\n" +
                "3QBGh4XBipyWopKwZ93HHaDVZAALi/2A+xTBtWdEo7XGUujKDvC2/aZKukfjpOiU\n" +
                "I8AhLAfjmlcD/UZ1QPh0mHsglRNCmpCwmwSXA9VNmhz+PiB+Dml4WWnKW/VHo2uj\n" +
                "TXxq7+efMU4H2fny3Se3KYOsFPFGZ1TNQSYlFuShWrHPtiLmUdPoP6CV2mML1tk+\n" +
                "l7DIIqXrQhLUKDACeM5roMx0kLhUWB8P+0uj1CNlNN4JRZlC7xFfqiMbFRU9Z4N6\n" +
                "YwIDAQAB\n" +
                "-----END PUBLIC KEY-----\n");
    }

    @Test
    public void rsaPublicPemX509() throws Exception {
        assertEncoding("rsaPublicPemX509.pem", Key.Format.PEM);
    }

    @Test
    public void rsaPublicOpenSsh() throws Exception {
        assertEncoding("rsaPublicOpenSsh.txt", OPENSSH);
    }

    @Test
    public void rsaPublicSsh2() throws Exception {
        assertEncoding("rsaPublicSsh2.txt", Key.Format.SSH2);
    }

    @Test
    public void rsaPublicJwk() throws Exception {
        assertJwksEncodingOfJwk("rsaPublicJwk.jwk");
    }

    @Test
    public void rsaPublicJwks() throws Exception {
        assertJwksEncoding("rsaPublicJwks.jwk");
    }

    @Test
    public void rsaPrivatePemPkcs1() throws Exception {
        assertEncoding("rsaPrivatePemPkcs1.pem", Key.Format.PEM, "" +
                "-----BEGIN PRIVATE KEY-----\n" +
                "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKlH8v7gYJQ0U+Zq\n" +
                "QXTllXX4MxBPcsx2EMKZbLTQI4ds7kdV9A8NKZnn1QzHRZxfJbfwPPotArv245xb\n" +
                "UUBm8B4Kcf2Lc7l/NSUVf/Ig1TpTv+gCXwdTYFPJYWk/4Yj3Q96yGLeEZPwmppXe\n" +
                "oe/KpBVn4mM91rB5hGukPNAAmD5PAgMBAAECgYA/C6TceASALdzxe7FVMAwyG3Yp\n" +
                "JO3EaFRlpW5vCPWygkdcGg8DbAuKXmVilPTAAE+z6a1MH2ddSd4LZZclPTE/48Yn\n" +
                "3il1CTWfE9EBfkL1sOkfKthRy/A3Fu+ElDHNC5V+EPmDu3pTAaKC77g+dqSufLuL\n" +
                "QckSkx32Jup9NkCqgQJBANhofPoENkH90NbnzXcI0Tw3OfMlxrfammYWboe1O+Al\n" +
                "9Wcv4XROSDMI1GZUwCRI84qubL4YJYq0431nZrbiuGkCQQDIQEFXRjJopuwZ15rl\n" +
                "U2ASw39zFAht2xwSQN+plxoEtvCxR8T6NZi5aS6cAzMEjOtPS4p0dJMyGTBVeqoj\n" +
                "46n3AkBLk/JRvrbURThyVXJEaCfqx77NVBwaiZXyoVLowjqvBZK2/tnWLKC6chL7\n" +
                "yg1wnqmvfUss+HHkB1iLq1kL9hJBAkAcjdUDXdYYSB0Ifk7u/lmHs2q7/RJKn+C7\n" +
                "1ZZO92XVYESn8sTqrLPPVGk6A9bFglaXYv0mJ+1JSoAy4B/cqDz3AkArL9IlrHqU\n" +
                "qf2rPROX3Q9gZikeVWgUZiCG4CGOHhZ/Cq7ybpVOhQggggK36MIvQaKnRTNoZt7y\n" +
                "q0MIxer5Jszg\n" +
                "-----END PRIVATE KEY-----\n");
    }

    @Test
    public void rsaPrivatePemPkcs8() throws Exception {
        assertEncoding("rsaPrivatePemPkcs8.pem", Key.Format.PEM);
    }

    @Test
    public void rsaPrivateOpenSsh() throws Exception {
        assertOpenSshPrivateEncoding("rsaPrivateOpenSsh.txt");
    }

    @Test
    public void rsaPrivateJwk() throws Exception {
        assertJwksEncodingOfJwk("rsaPrivateJwk.jwk");
    }

    @Test
    public void rsaPrivateJwks() throws Exception {
        assertJwksEncoding("rsaPrivateJwks.jwk");
    }

    @Test
    public void dsaPublicPemX509() throws Exception {
        assertEncoding("dsaPublicPemX509.pem", Key.Format.PEM);
    }

    @Test
    public void dsaPublicOpenSsh() throws Exception {
        assertEncoding("dsaPublicOpenSsh.txt", OPENSSH);
    }

    @Test
    public void dsaPublicSsh2() throws Exception {
        assertEncoding("dsaPublicSsh2.txt", Key.Format.SSH2);
    }

    @Test
    public void dsaPublicJwk() throws Exception {
        assertJwksEncodingOfJwk("dsaPublicJwk.jwk");
    }

    @Test
    public void dsaPublicJwks() throws Exception {
        assertJwksEncoding("dsaPublicJwks.jwk");
    }

    @Test
    public void dsaPrivatePemPkcs1() throws Exception {
        assertEncoding("dsaPrivatePemPkcs1.pem", Key.Format.PEM, "" +
                "-----BEGIN PRIVATE KEY-----\n" +
                "MIIBSgIBADCCASsGByqGSM44BAEwggEeAoGBAN9w84QLHWmzl/gY2Xh/CnM7hfTs\n" +
                "Ul6Z89NUmhOFfs/wzO54Pl84qKjWmlhJO9VGFwsMRbw0EqGgS1eBngv+DR/eMAN+\n" +
                "0KnLTPTNEajKP/ibTRf3sI3Rf7UTYhSp7W5r5FB8TN39chg9JQUR7c0ALOdbyDL8\n" +
                "d+yhB5SzLEAWQ4QTAhUAnLvRijCScl/IKOsNYJ/d14tfxA8CgYBJYC9VGyg80b7D\n" +
                "F8+fHKfezGEjjRgJOVMJQA946vA3A+cntFUU+Y1LayXJ2y+0lbLE8W5EUWclzQX6\n" +
                "2BugCgRIx5nLLgTDvKhEao1MK0r81HhCF80lYJHLHtfECWb3Mru9HCu6sV77qoQh\n" +
                "6LJ7AmAwU4Fl6udlRMKbIxxFgYmUrwQWAhR/gxpjJmDuGd5fb+rSFUlGNHo3pQ==\n" +
                "-----END PRIVATE KEY-----\n");
    }

    @Test
    public void dsaPrivatePemPkcs8() throws Exception {
        assertEncoding("dsaPrivatePemPkcs8.pem", Key.Format.PEM);
    }

    @Test
    public void dsaPrivateOpenSsh() throws Exception {
        assertOpenSshPrivateEncoding("dsaPrivateOpenSsh.txt");
    }

    @Test
    public void dsaPrivateJwk() throws Exception {
        assertJwksEncodingOfJwk("dsaPrivateJwk.jwk");
    }

    @Test
    public void dsaPrivateJwks() throws Exception {
        assertJwksEncoding("dsaPrivateJwks.jwk");
    }

    @Test
    public void ecPublicPemX509() throws Exception {
        assertEncoding("ecPublicPemX509.pem", Key.Format.PEM);
    }

    @Test
    public void ecPublicOpenSsh() throws Exception {
        assertEncoding("ecPublicOpenSsh.txt", OPENSSH);
    }

    @Test
    @Ignore("Implement")
    public void ecPublicSsh2() throws Exception {
        assertEncoding("ecPublicSsh2.txt", Key.Format.SSH2);
    }

    @Test
    public void ecPublicJwk() throws Exception {
        assertJwksEncodingOfJwk("ecPublicJwk.jwk");
    }

    @Test
    public void ecPublicJwks() throws Exception {
        assertJwksEncoding("ecPublicJwks.jwk");
    }

    @Test
    @Ignore("Implement")
    public void ecPrivatePemPkcs1() throws Exception {
        assertEncoding("ecPrivatePemPkcs1.pem", Key.Format.PEM);
    }

    @Test
    public void ecPrivatePemPkcs8() throws Exception {
        assertEncoding("ecPrivatePemPkcs8.pem", Key.Format.PEM, "-----BEGIN PRIVATE KEY-----\n" +
                "MIGGAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBGwwagIBAQQgc7kJYR49ciVZd2aN\n" +
                "RvMYYyBghMb9/LVyXzc038qaXc0hQwNBBOMoNOOSXTJRN0PGIURSMsLVBpEAeoVo\n" +
                "89EmBt9MsiQpnNxVETMrLjUV2T6FHWSgVUOsYULoSsklap3YDmZg0B8=\n" +
                "-----END PRIVATE KEY-----\n");
    }

    @Test
    public void ecPrivateOpenSsh() throws Exception {
        assertOpenSshPrivateEncoding("ecPrivateOpenSsh.txt");
    }

    @Test
    public void ecPrivateJwk() throws Exception {
        assertJwksEncodingOfJwk("ecPrivateJwk.jwk");
    }

    @Test
    public void ecPrivateJwks() throws Exception {
        assertJwksEncoding("ecPrivateJwks.jwk");
    }

    @Test
    public void allKeyTypesJwks() throws Exception {
        assertJwksEncoding("allKeyTypesJwks.jwk");
    }

    @Test
    public void authorizedKeysFile() throws Exception {
        assertEncoding("authorized_keys", OPENSSH);
    }

    private void assertEncoding(final String file, final Key.Format format) throws IOException {
        final byte[] expected = resource.bytes(file);
        final List<Key> keys = Keys.decodeSet(expected);

        final byte[] actual = Keys.encodeSet(keys, format);
        assertEquals(new String(expected), new String(actual));
    }

    /**
     * OpenSSH Private Key encodings have a random number in them,
     * so we assert both that the strings don't exactly match (i.e.
     * there is a random component) and also that the the majority
     * of lines do match.
     */
    private void assertOpenSshPrivateEncoding(final String file) throws IOException {
        final String expected = new String(resource.bytes(file));
        final List<Key> keys = Keys.decodeSet(expected);

        final String actual = new String(Keys.encodeSet(keys, OPENSSH));

        assertNotEquals(expected, actual);

        final List<String> expectedLines = Arrays.asList(expected.split("\n\r?"));
        final List<String> actualLines = Arrays.asList(actual.split("\n\r?"));

        final long matching = actualLines.stream()
                .filter(expectedLines::contains)
                .count();

        assertTrue(matching >= expectedLines.size() - 3);
    }

    private void assertEncoding(final String file, final Key.Format format, final String expected) throws IOException {
        final List<Key> keys = Keys.decodeSet(resource.bytes(file));

        final byte[] actual = Keys.encodeSet(keys, format);
        assertEquals(expected, new String(actual));
    }

    /**
     * Read in a JWK file and assert that it can be converted to a JWKS file
     * via calling encodeSet
     */
    private void assertJwksEncodingOfJwk(final String file) throws IOException, JsonParserException {
        final String expected = new String(resource.bytes(file));
        final List<Key> keys = Keys.decodeSet(expected);

        final byte[] encodedSet = Keys.encodeSet(keys, JWK);
        final JsonObject set = JsonParser.object().from(new ByteArrayInputStream(encodedSet));
        assertTrue(set.containsKey("keys"));
        final JsonObject key = set.getObject("keys");

        final String actual = JsonWriter.string(key);
        JsonAsserts.assertJson(expected, actual);
    }

    private void assertJwksEncoding(final String file) throws IOException {
        final String expected = new String(resource.bytes(file));
        final List<Key> keys = Keys.decodeSet(expected);

        final String actual = new String(Keys.encodeSet(keys, JWK));

        JsonAsserts.assertJson(expected, actual);
    }
}
