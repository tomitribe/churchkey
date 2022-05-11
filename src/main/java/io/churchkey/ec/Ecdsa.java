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
package io.churchkey.ec;

import lombok.Builder;
import lombok.Data;
import io.churchkey.Spec;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;

import static io.churchkey.Key.Algorithm.EC;

public class Ecdsa {

    @Data
    @Builder(builderClassName = "Builder")
    public static class Public implements Spec<ECPublicKey, ECPublicKey> {
        private final String curveName;
        private final Curve curve;
        private final ECParameterSpec spec;
        private final BigInteger x;
        private final BigInteger y;

        public Public(String curveName, Curve curve, ECParameterSpec spec, final BigInteger x, final BigInteger y) {
            this.x = x;
            this.y = y;
            if (curve == null && curveName == null && spec == null) {
                throw new IllegalArgumentException("Curve, curveName or spec must be specified");
            }

            if (curve == null && curveName != null) curve = Curve.resolve(curveName);
            if (curveName == null && curve != null) curveName = curve.name();
            if (spec == null && curve != null) spec = curve.getParameterSpec();
            if (spec == null) throw new IllegalArgumentException("ECParameterSpec, Curve or curve name not supplied");
            this.curveName = curveName;
            this.curve = curve;
            this.spec = spec;
        }

        @Override
        public Spec<ECPublicKey, ECPublicKey> toPublic() {
            return this;
        }

        @Override
        public ECPublicKey toKey() {
            return (ECPublicKey) EC.getKeyFactory()
                    .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
        }
    }

    @Data
    @Builder(builderClassName = "Builder")
    public static class Private implements Spec<ECPrivateKey, ECPublicKey> {
        private final String curveName;
        private final Curve curve;
        private final ECParameterSpec spec;
        private final BigInteger x;
        private final BigInteger y;
        private final BigInteger d;

        public Private(String curveName, Curve curve, ECParameterSpec spec, final BigInteger x, final BigInteger y, final BigInteger d) {
            this.x = x;
            this.y = y;
            this.d = d;

            if (curve == null && curveName == null && spec == null) {
                throw new IllegalArgumentException("Curve, curveName or spec must be specified");
            }

            if (curve == null && curveName != null) curve = Curve.resolve(curveName);
            if (curveName == null && curve != null) curveName = curve.name();
            if (spec == null && curve != null) spec = curve.getParameterSpec();
            if (spec == null) throw new IllegalArgumentException("ECParameterSpec, Curve or curve name not supplied");
            this.curveName = curveName;
            this.curve = curve;
            this.spec = spec;
        }

        @Override
        public Spec<ECPublicKey, ECPublicKey> toPublic() {
            return Public.builder()
                    .curveName(curveName)
                    .curve(curve)
                    .spec(spec)
                    .x(x)
                    .y(y)
                    .build();
        }

        @Override
        public ECPrivateKey toKey() {
            return (ECPrivateKey) EC.getKeyFactory()
                    .generatePrivate(new ECPrivateKeySpec(d, spec));
        }

    }
}
