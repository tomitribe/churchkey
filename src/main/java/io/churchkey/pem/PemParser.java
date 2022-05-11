/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.churchkey.pem;

import io.churchkey.Decoder;
import io.churchkey.util.Pem;
import io.churchkey.Key;
import io.churchkey.util.Utils;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class PemParser implements Key.Format.Parser {

    private final PemDecoder decoder = new PemDecoder();

    @Override
    public Key decode(final byte[] bytes) {
        return decoder.decode(bytes);
    }

    @Override
    public byte[] encode(final Key key) {
        switch (key.getType()) {
            case PUBLIC: {
                return BeginPublicKey.encode(key);
            }
            case PRIVATE: {
                return BeginPrivateKey.encode(key);
            }
            case SECRET:
                throw new UnsupportedOperationException("Secret keys cannot be exported to PEM format.");
            default:
                throw new UnsupportedOperationException("Unsupported key type: " + key.getType());
        }
    }


    public static class PemDecoder implements Decoder {

        private final Map<String, Function<byte[], Key>> converters = new HashMap<>();

        {
            converters.put("PRIVATE KEY", BeginPrivateKey::decode);
            converters.put("PUBLIC KEY", BeginPublicKey::decode);
            converters.put("RSA PRIVATE KEY", BeginRsaPrivateKey::decode);
            converters.put("RSA PUBLIC KEY", BeginRsaPublicKey::decode);
            converters.put("DSA PRIVATE KEY", BeginDsaPrivateKey::decode);
            converters.put("EC PRIVATE KEY", BeginEcPrivateKey::decode);
//            converters.put("EC PUBLIC KEY", BeginEcPublicKey::decode);
        }

        public PemDecoder() {
        }


        @Override
        public Key decode(final byte[] key) {
            if (!Utils.startsWith("-----", key)) return null;

            final Pem pem = Pem.parse(key);

            final Function<byte[], Key> converter = converters.get(pem.getType());

            if (converter == null) {
                throw new UnsupportedOperationException(String.format("Unsupported PEM format '%s'", pem.getType()));
            }

            return converter.apply(pem.getData());
        }
    }
}
