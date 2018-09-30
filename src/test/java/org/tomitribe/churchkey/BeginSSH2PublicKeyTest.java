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

public class BeginSSH2PublicKeyTest {

    @Test
    public void testRSADecode1024() throws Exception {
        assertRSADecode(1024, 256);
    }

    @Test
    public void testRSADecode2048() throws Exception {
        assertRSADecode(2048, 256);
    }

    private void assertRSADecode(final int rsaBits, final int shaBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource("rsa", rsaBits, shaBits);

        final KeyFactory factory = KeyFactory.getInstance("RSA");
        final RSAPublicKey expected = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.ssh2"));
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());

        final RSAPublicKey actual = (RSAPublicKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getModulus(), actual.getModulus());
    }

    @Test
    public void testDSADecode1024() throws Exception {
        assertDSADecode(1024, 256);
    }

    private void assertDSADecode(final int rsaBits, final int shaBits) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        final Resource resource = Resource.resource("dsa", rsaBits, shaBits);

        final KeyFactory factory = KeyFactory.getInstance("DSA");
        final DSAPublicKey expected = (DSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = Keys.decode(resource.bytes("public.ssh2"));
        assertEquals(Key.Algorithm.DSA, key.getAlgorithm());
        assertEquals(Key.Type.PUBLIC, key.getType());
        assertEquals(Key.Format.SSH2, key.getFormat());

        final DSAPublicKey actual = (DSAPublicKey) key.getKey();

        assertEquals(expected.getY(), actual.getY());
        assertEquals(expected.getParams().getG(), actual.getParams().getG());
        assertEquals(expected.getParams().getP(), actual.getParams().getP());
        assertEquals(expected.getParams().getQ(), actual.getParams().getQ());
    }
}