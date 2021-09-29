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
package org.tomitribe.churchkey.dsa;

import lombok.Builder;
import lombok.Data;
import org.tomitribe.churchkey.Spec;

import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

import static org.tomitribe.churchkey.Key.Algorithm.DSA;

public class Dsa {

    @Data
    @Builder(builderClassName = "Builder")
    public static class Public implements Spec<DSAPublicKey, DSAPublicKey> {
        private BigInteger y;
        private BigInteger p;
        private BigInteger q;
        private BigInteger g;

        @Override
        public Spec<DSAPublicKey, DSAPublicKey> toPublic() {
            return this;
        }

        @Override
        public DSAPublicKey toKey() {
            return (DSAPublicKey) DSA.getKeyFactory()
                    .generatePublic(new DSAPublicKeySpec(y, p, q, g));
        }
    }

    @Data
    @Builder(builderClassName = "Builder")
    public static class Private implements Spec<DSAPrivateKey, DSAPublicKey> {
        private BigInteger p;
        private BigInteger q;
        private BigInteger g;
        private BigInteger x;
        private BigInteger y;


        @Override
        public Spec<DSAPublicKey, DSAPublicKey> toPublic() {
            final BigInteger y = this.y == null ? g.modPow(x, p) : this.y;

            return Public.builder()
                    .g(g)
                    .p(p)
                    .q(q)
                    .y(y)
                    .build();
        }

        @Override
        public DSAPrivateKey toKey() {
            return (DSAPrivateKey) DSA.getKeyFactory()
                    .generatePrivate(new DSAPrivateKeySpec(x, p, q, g));
        }
    }
}
