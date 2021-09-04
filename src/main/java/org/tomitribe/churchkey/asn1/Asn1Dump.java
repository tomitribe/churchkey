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
package org.tomitribe.churchkey.asn1;

import org.tomitribe.util.IO;
import org.tomitribe.util.Pipe;

import java.io.File;
import java.io.IOException;

public class Asn1Dump {

    private Asn1Dump() {
    }

    public static void print(final byte[] bytes) throws IOException {
        final File der = File.createTempFile("der", ".dump");
        IO.copy(bytes, der);

        final ProcessBuilder builder = new ProcessBuilder("openssl", "asn1parse", "-i", "-inform", "DER", "-in", der.getAbsolutePath(), "-dump");
        final Process process = builder.start();
        Pipe.pipe(process.getInputStream(), System.out);
        Pipe.pipe(process.getErrorStream(), System.err);
        try {
            final int i = process.waitFor();
            if (i != 0) {
                throw new IllegalStateException("Exit code " + i);
            }
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }
}
