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
package org.tomitribe.churchkey;

import org.junit.Ignore;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Intentionally simplistic test for the purposes of tracking
 * which encoding scenarios are implemented and which are not.
 *
 * More exhaustive tests for each scenario are elsewhere.
 */
public class KeyDecodeTest {

    private final Resource resource = Resource.resource(this.getClass());

    @Test
    public void rsaPublicPemPkcs1() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPublicPemPkcs1.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPublicPemX509() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPublicPemX509.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPublicOpenSsh() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPublicOpenSsh.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPublicSsh2() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPublicSsh2.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPublicJwk() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPublicJwk.jwk"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPrivatePemPkcs1() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPrivatePemPkcs1.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPrivatePemPkcs8() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPrivatePemPkcs8.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPrivateOpenSsh() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPrivateOpenSsh.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    @Ignore("This format does not appear to exist in the wild")
    public void rsaPrivateSsh2() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPrivateSsh2.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    public void rsaPrivateJwk() throws Exception {
        final Key key = Keys.decode(resource.bytes("rsaPrivateJwk.jwk"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
    }

    @Test
    @Ignore("This format does not appear to exist in the wild")
    public void dsaPublicPemPkcs1() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPublicPemPkcs1.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPublicPemX509() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPublicPemX509.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPublicOpenSsh() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPublicOpenSsh.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPublicSsh2() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPublicSsh2.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPublicJwk() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPublicJwk.jwk"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPrivatePemPkcs1() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPrivatePemPkcs1.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPrivatePemPkcs8() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPrivatePemPkcs8.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPrivateOpenSsh() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPrivateOpenSsh.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    @Ignore("This format does not appear to exist in the wild")
    public void dsaPrivateSsh2() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPrivateSsh2.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    public void dsaPrivateJwk() throws Exception {
        final Key key = Keys.decode(resource.bytes("dsaPrivateJwk.jwk"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
    }

    @Test
    @Ignore("This format does not appear to exist in the wild")
    public void ecPublicPemPkcs1() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPublicPemPkcs1.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    public void ecPublicPemX509() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPublicPemX509.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    @Ignore("Implement")
    public void ecPublicOpenSsh() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPublicOpenSsh.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    @Ignore("Implement")
    public void ecPublicSsh2() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPublicSsh2.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    public void ecPublicJwk() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPublicJwk.jwk"));
        assertNotNull(key);
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    @Ignore("Implement")
    public void ecPrivatePemPkcs1() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPrivatePemPkcs1.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    public void ecPrivatePemPkcs8() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPrivatePemPkcs8.pem"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.PEM, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    public void ecPrivateOpenSsh() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPrivateOpenSsh.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    @Ignore("This format does not appear to exist in the wild")
    public void ecPrivateSsh2() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPrivateSsh2.txt"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    @Test
    public void ecPrivateJwk() throws Exception {
        final Key key = Keys.decode(resource.bytes("ecPrivateJwk.jwk"));
        assertNotNull(key);
        assertEquals(Key.Type.PRIVATE, key.getType());
        assertEquals(Key.Format.JWK, key.getFormat());
        assertEquals(Key.Algorithm.EC, key.getAlgorithm());
    }

    public static void _main(String[] args) {
        final List<String> methods = Arrays.asList("rsaPublicPemPkcs1",
                "rsaPublicPemX509",
                "rsaPublicOpenSsh",
                "rsaPublicSsh2",
                "rsaPublicJwk",
                "rsaPrivatePemPkcs1",
                "rsaPrivatePemPkcs8",
                "rsaPrivateOpenSsh",
                "rsaPrivateSsh2",
                "rsaPrivateJwk",
                "dsaPublicPemPkcs1",
                "dsaPublicPemX509",
                "dsaPublicOpenSsh",
                "dsaPublicSsh2",
                "dsaPublicJwk",
                "dsaPrivatePemPkcs1",
                "dsaPrivatePemPkcs8",
                "dsaPrivateOpenSsh",
                "dsaPrivateSsh2",
                "dsaPrivateJwk",
                "ecPublicPemPkcs1",
                "ecPublicPemX509",
                "ecPublicOpenSsh",
                "ecPublicSsh2",
                "ecPublicJwk",
                "ecPrivatePemPkcs1",
                "ecPrivatePemPkcs8",
                "ecPrivateOpenSsh",
                "ecPrivateSsh2",
                "ecPrivateJwk"
        );

        for (final String method : methods) {
            final String type = method.contains("Public") ? "PUBLIC" : "PRIVATE";
            final String format = getFormat(method.toLowerCase());
            final String algorithm = getAlgorithm(method.toLowerCase());
            System.out.printf("    @Test\n" +
                    "    public void %s() throws Exception {\n" +
                    "        final Key key = Keys.decode(resource.bytes(\"%s.%s\"));\n" +
                    "        assertNotNull(key);\n" +
                    "        assertEquals(Key.Type.%s, key.getType());\n" +
                    "        assertEquals(Key.Format.%s, key.getFormat());\n" +
                    "        assertEquals(Key.Algorithm.%s, key.getAlgorithm());\n" +
                    "    }\n" +
                    "\n", method, method, format.toLowerCase(), type, format, algorithm);
        }
    }

    private static String getAlgorithm(final String method) {
        if (method.contains("rsa")) return "RSA";
        if (method.contains("dsa")) return "DSA";
        if (method.contains("ec")) return "EC";
        throw new UnsupportedOperationException(method);
    }

    private static String getFormat(final String method) {
        if (method.contains("pem")) return "PEM";
        if (method.contains("jwk")) return "JWK";
        if (method.contains("openssh")) return "OPENSSH";
        if (method.contains("ssh2")) return "SSH2";
        throw new UnsupportedOperationException(method);
    }
}
