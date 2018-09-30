package org.tomitribe.churchkey;

import org.junit.Test;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class OpenSSHPublicKeyTest {

    @Test
    public void testRSADecode1024() throws Exception {
        assertDecodeRsaPublicKey(1024, 256);
    }

    @Test
    public void testRSADecode2048() throws Exception {
        assertDecodeRsaPublicKey(2048, 256);
    }

    private void assertDecodeRsaPublicKey(final int rsaBits, final int shaBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource("rsa", rsaBits, shaBits);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPublicKey expected = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.openssh"));
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());

        final RSAPublicKey actual = (RSAPublicKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getModulus(), actual.getModulus());
    }

    @Test
    public void testDSADecode1024() throws Exception {
        assertDecodeRsaPublicKey(1024, 256);
    }

    @Test
    public void testDSADecode2048() throws Exception {
        assertDecodeRsaPublicKey(2048, 256);
    }

    private void assertDecodeDsaPublicKey(final int rsaBits, final int shaBits) throws Exception {
        final Resource resource = Resource.resource("dsa", rsaBits, shaBits);

        final KeyFactory rsa = KeyFactory.getInstance("DSA");
        final DSAPublicKey expected = (DSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.openssh"));
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.OPENSSH, key.getFormat());

        final DSAPublicKey actual = (DSAPublicKey) key.getKey();

        assertEquals(expected.getY(), actual.getY());
        assertEquals(expected.getParams().getG(), actual.getParams().getG());
        assertEquals(expected.getParams().getQ(), actual.getParams().getQ());
        assertEquals(expected.getParams().getP(), actual.getParams().getP());
    }

    @Test
    public void testEncode1024() throws Exception {
        final Resource resource = Resource.resource("rsa", 1024, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPublicKey rsaPublicKey = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final String expected = new String(resource.bytes("public.openssh"), "UTF-8");
        final String actual = OpenSSH.formatSshPublicKey(rsaPublicKey, "dblevins@mingus.lan");

        assertEquals(expected, actual);
    }

}