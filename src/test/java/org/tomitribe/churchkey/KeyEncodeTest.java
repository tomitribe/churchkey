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
package org.tomitribe.churchkey;

import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;

public class KeyEncodeTest {

    @Test
    public void rsaPem() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = generator.generateKeyPair();
        final RSAPrivateCrtKey expected = (RSAPrivateCrtKey) pair.getPrivate();


    }

}
