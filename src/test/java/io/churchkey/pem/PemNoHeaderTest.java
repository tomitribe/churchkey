/* =====================================================================
 *
 * Copyright (c) 2011 David Blevins.  All rights reserved.
 *
 * =====================================================================
 */
package io.churchkey.pem;

import io.churchkey.Keys;
import io.churchkey.Resource;
import io.churchkey.util.Pem;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static io.churchkey.KeyAsserts.assertDsaPrivateKey;
import static io.churchkey.KeyAsserts.assertDsaPublicKey;
import static io.churchkey.KeyAsserts.assertEcPrivateKey;
import static io.churchkey.KeyAsserts.assertEcPublicKey;
import static io.churchkey.KeyAsserts.assertRsaPrivateKey;
import static io.churchkey.KeyAsserts.assertRsaPublicKey;

public class PemNoHeaderTest {

    @Test
    public void dsaPrivatePemPkcs1() {
        assertUnwrappedPem("dsaPrivatePemPkcs1.pem");
    }

    @Test
    public void dsaPrivatePemPkcs8() {
        assertUnwrappedPem("dsaPrivatePemPkcs8.pem");
    }

    @Test
    public void dsaPublicPemX509() {
        assertUnwrappedPem("dsaPublicPemX509.pem");
    }

    @Test
    public void ecPrivatePemPkcs1() {
        assertUnwrappedPem("ecPrivatePemPkcs1.pem");
    }

    @Test
    public void ecPrivatePemPkcs8() {
        assertUnwrappedPem("ecPrivatePemPkcs8.pem");
    }

    @Test
    public void ecPublicPemX509() {
        assertUnwrappedPem("ecPublicPemX509.pem");
    }

    @Test
    public void rsaPrivatePemPkcs1() {
        assertUnwrappedPem("rsaPrivatePemPkcs1.pem");
    }

    @Test
    public void rsaPrivatePemPkcs8() {
        assertUnwrappedPem("rsaPrivatePemPkcs8.pem");
    }

    @Test
    public void rsaPublicPemPkcs1() {
        assertUnwrappedPem("rsaPublicPemPkcs1.pem");
    }

    @Test
    public void rsaPublicPemX509() {
        assertUnwrappedPem("rsaPublicPemX509.pem");
    }


    private void assertUnwrappedPem(final String file) {
        final byte[] bytes;
        try {
            final Resource resource = Resource.resource(PemNoHeaderTest.class);
            bytes = resource.bytes(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        final java.security.Key expected = Keys.decode(bytes).getKey();

        final byte[] base64BytesWithNoHeader = Base64.getEncoder().encode(Pem.parse(bytes).getData());
        final java.security.Key actual = Keys.decode(base64BytesWithNoHeader).getKey();

        if (actual instanceof RSAPrivateCrtKey) {
            assertRsaPrivateKey((RSAPrivateCrtKey) expected, (RSAPrivateCrtKey) actual);
        } else if (actual instanceof RSAPublicKey) {
            assertRsaPublicKey((RSAPublicKey) expected, (RSAPublicKey) actual);
        } else if (actual instanceof DSAPrivateKey) {
            assertDsaPrivateKey((DSAPrivateKey) expected, (DSAPrivateKey) actual);
        } else if (actual instanceof DSAPublicKey) {
            assertDsaPublicKey((DSAPublicKey) expected, (DSAPublicKey) actual);
        } else if (actual instanceof ECPrivateKey) {
            assertEcPrivateKey((ECPrivateKey) expected, (ECPrivateKey) actual);
        } else if (actual instanceof ECPublicKey) {
            assertEcPublicKey((ECPublicKey) expected, (ECPublicKey) actual);
        } else {
            Assert.fail("Unexpected key type " + actual.getClass().getName());
        }
    }

}
