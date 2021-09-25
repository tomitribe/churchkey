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

import org.tomitribe.churchkey.util.Pem;
import org.tomitribe.util.IO;
import org.tomitribe.util.Pipe;
import org.tomitribe.util.PrintString;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

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

    public static String dump(final byte[] bytes) throws IOException {
        final File der = File.createTempFile("der", ".dump");

        if (bytes[0] == '-' && bytes[1] == '-'){
            final Pem pem = Pem.parse(bytes);
            IO.copy(pem.getData(), der);
        } else {
            IO.copy(bytes, der);
        }

        final PrintString err = new PrintString();
        final PrintString out = new PrintString();
        final ProcessBuilder builder = new ProcessBuilder("openssl", "asn1parse", "-i", "-inform", "DER", "-in", der.getAbsolutePath(), "-dump");
        final Process process = builder.start();
        final Future<Pipe> o = Pipe.pipe(process.getInputStream(), out);
        final Future<Pipe> e = Pipe.pipe(process.getErrorStream(), err);
        try {
            final int i = process.waitFor();
            o.get();
            e.get();
            if (i != 0) {
                throw new IllegalStateException("Exit code " + i + "\n" + err);
            }
        } catch (InterruptedException | ExecutionException exception) {
            throw new IllegalStateException(exception);
        } finally {
            out.close();
            err.close();
            der.delete();
        }
        return out.toString();
    }
}
