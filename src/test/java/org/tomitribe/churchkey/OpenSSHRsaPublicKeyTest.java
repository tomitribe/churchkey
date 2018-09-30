package org.tomitribe.churchkey;

import org.junit.Test;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class OpenSSHRsaPublicKeyTest {

    @Test
    public void testDecode1024() throws Exception {
        assertDecodeOpenSSHPublicKey(1024, 256);
    }

    @Test
    public void testDecode2048() throws Exception {
        assertDecodeOpenSSHPublicKey(2048, 256);
    }

    @Test
    public void testEncode1024() throws Exception {
        final Resource resource = Resource.resource(1024, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final String expected = new String(resource.bytes("public.openssh"), "UTF-8");
        final String actual = OpenSSH.formatSshPublicKey(rsaPublicKey, "dblevins@mingus.lan");

        assertEquals(expected, actual);
    }

    private void assertDecodeOpenSSHPublicKey(final int rsaBits, final int shaBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource(rsaBits, shaBits);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPublicKey expected = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final RSAPublicKey actual = (RSAPublicKey) Keys.readPublicKey(resource.bytes("public.openssh"));

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getModulus(), actual.getModulus());
    }
}