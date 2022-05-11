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
package io.churchkey.rsa;

import lombok.Builder;
import lombok.Data;
import io.churchkey.Spec;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import static io.churchkey.Key.Algorithm.RSA;

public class Rsa {

    @Data
    @Builder(builderClassName = "Builder")
    public static class Public implements Spec<RSAPublicKey, RSAPublicKey> {
        private final BigInteger modulus;
        private final BigInteger publicExponent;

        @Override
        public RSAPublicKey toKey() {
            return (RSAPublicKey) RSA.getKeyFactory()
                    .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        }

        @Override
        public Spec<RSAPublicKey, RSAPublicKey> toPublic() {
            return this;
        }
    }

    @Data
    @Builder(builderClassName = "Builder")
    public static class Private implements Spec<RSAPrivateCrtKey, RSAPublicKey> {
        private final BigInteger modulus;
        private final BigInteger publicExponent;
        private final BigInteger privateExponent;
        private final BigInteger primeP;
        private final BigInteger primeQ;
        private final BigInteger primeExponentP;
        private final BigInteger primeExponentQ;
        private final BigInteger crtCoefficient;

        @Override
        public RSAPrivateCrtKey toKey() {
            return (RSAPrivateCrtKey) RSA.getKeyFactory()
                    .generatePrivate(new RSAPrivateCrtKeySpec(
                            modulus,
                            publicExponent,
                            privateExponent,
                            primeP,
                            primeQ,
                            primeExponentP,
                            primeExponentQ,
                            crtCoefficient
                    ));
        }

        @Override
        public Spec<RSAPublicKey, RSAPublicKey> toPublic() {
            return Public.builder()
                    .modulus(modulus)
                    .publicExponent(publicExponent)
                    .build();
        }
    }
}
