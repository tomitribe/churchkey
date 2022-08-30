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
package io.churchkey;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class Generate {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        final File dir = new File("/Users/dblevins/work/tomitribe/churchkey/src/test/resources/der");

        for (final File file : dir.listFiles()) {
            final int anInt;
            try (final DataInputStream stream = new DataInputStream(Files.newInputStream(file.toPath()))) {
                anInt = stream.readInt();
            }
            Files.write(new File(file.getAbsolutePath() + ".bin").toPath(), Integer.toBinaryString(anInt).getBytes());
        }
    }

    public static void generate(final File dir) {
        for (int i = 512; i < 10000; i += 1) {
            try {
                generate(dir, "dsa", i);
            } catch (Exception e) {
//                e.printStackTrace();
            }
        }
    }

    public static void generate(final File dir, final String algorithm, final int size) throws NoSuchAlgorithmException, IOException {
        final KeyPairGenerator rsa = KeyPairGenerator.getInstance(algorithm.toUpperCase());
        rsa.initialize(size);

        for (int i = 0; i < 100; i++) {
            final KeyPair keyPair = rsa.generateKeyPair();
            Files.write(new File(dir, algorithm + "-" + size + "-public-pkcs8.der." + i).toPath(), keyPair.getPublic().getEncoded());
            Files.write(new File(dir, algorithm + "-" + size + "-private-pkcs8.der." + i).toPath(), keyPair.getPrivate().getEncoded());
        }
    }


}
