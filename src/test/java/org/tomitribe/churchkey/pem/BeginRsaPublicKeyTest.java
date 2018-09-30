package org.tomitribe.churchkey.pem;

import org.junit.Test;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.PemDecoder;
import org.tomitribe.churchkey.Resource;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.*;

public class BeginRsaPublicKeyTest {

    @Test
    public void testDecode() throws Exception {
        final Resource resource = Resource.resource(1024, 256);

        final KeyFactory rsa = KeyFactory.getInstance("RSA");
        final RSAPublicKey expected = (RSAPublicKey) rsa.generatePublic(new X509EncodedKeySpec(resource.bytes("public.pkcs8.der")));

        final Key key = new PemDecoder().decode(resource.bytes("public.pkcs1.pem"));
        assertEquals(Key.Algorithm.RSA, key.getAlgorithm());

        final RSAPublicKey actual = (RSAPublicKey) key.getKey();

        assertEquals(expected.getPublicExponent(), actual.getPublicExponent());
        assertEquals(expected.getModulus(), actual.getModulus());

    }
}