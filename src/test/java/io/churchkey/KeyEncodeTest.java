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

import org.junit.Ignore;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Intentionally simplistic test for the purposes of tracking
 * which encoding scenarios are implemented and which are not.
 *
 * More exhaustive tests for each scenario are elsewhere.
 */
public class KeyEncodeTest {

    @Test
    public void rsaPublicPem() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.PEM));

        assertNotNull(content);
        assertTrue(content.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(content.endsWith("-----END PUBLIC KEY-----\n"));
    }

    @Test
    public void rsaPublicOpenSsh() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.OPENSSH));
        assertNotNull(content);
        assertTrue(content.startsWith("ssh-rsa "));
    }

    @Test
    public void rsaPublicSsh2() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.SSH2));

        assertNotNull(content);
    }

    @Test
    public void rsaPublicJwk() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.JWK));

        assertNotNull(content);
    }

    @Test
    public void rsaPrivatePem() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPrivate()).encode(Key.Format.PEM));

        assertNotNull(content);
        assertTrue(content.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(content.endsWith("-----END PRIVATE KEY-----\n"));
    }

    @Test
    public void rsaPrivateOpenSsh() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) pair.getPrivate();

        final String content = new String(Keys.of(expected).encode(Key.Format.OPENSSH));

        assertNotNull(content);
    }

    @Test
    public void rsaPrivateJwk() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) pair.getPrivate();

        final String content = new String(Keys.of(expected).encode(Key.Format.JWK));

        assertNotNull(content);
    }

    @Test
    public void dsaPublicPem() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.PEM));

        assertNotNull(content);
        assertTrue(content.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(content.endsWith("-----END PUBLIC KEY-----\n"));
    }

    @Test
    public void dsaPublicOpenSsh() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.OPENSSH));

        assertNotNull(content);
    }

    @Test
    public void dsaPublicSsh2() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.SSH2));

        assertNotNull(content);
    }

    @Test
    public void dsaPublicJwk() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.JWK));

        assertNotNull(content);
    }

    @Test
    public void dsaPrivatePem() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPrivate()).encode(Key.Format.PEM));

        assertNotNull(content);
    }

    @Test
    public void dsaPrivateOpenSsh() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPrivate()).encode(Key.Format.OPENSSH));

        assertNotNull(content);
    }

    @Test
    public void dsaPrivateJwk() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPrivate()).encode(Key.Format.JWK));

        assertNotNull(content);
    }

    @Test
    public void ecPublicPem() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.PEM));

        assertNotNull(content);
        assertTrue(content.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(content.endsWith("-----END PUBLIC KEY-----\n"));
    }

    @Test
    public void ecPublicOpenSsh() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.OPENSSH));

        assertNotNull(content);
        assertTrue(content.startsWith("ecdsa-sha2-nistp256 AAAA"));
    }

    @Test
    public void ecPublicSsh2() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.SSH2));

        assertNotNull(content);
    }

    @Test
    public void ecPublicJwk() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPublic()).encode(Key.Format.JWK));

        assertNotNull(content);
    }

    @Test
    public void ecPrivatePem() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPrivate()).encode(Key.Format.PEM));

        assertNotNull(content);
        assertTrue(content.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(content.endsWith("-----END PRIVATE KEY-----\n"));
    }

    @Test
    public void ecPrivateOpenSsh() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair).encode(Key.Format.OPENSSH));

        assertNotNull(content);
    }

    @Test
    public void ecPrivateJwk() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        final KeyPair pair = generator.generateKeyPair();

        final String content = new String(Keys.of(pair.getPrivate()).encode(Key.Format.JWK));

        assertNotNull(content);
    }
}
