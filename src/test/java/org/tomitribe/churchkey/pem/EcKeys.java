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
package org.tomitribe.churchkey.pem;

import org.junit.Assume;
import org.tomitribe.churchkey.InvalidPrivateKeySpecException;
import org.tomitribe.churchkey.Key;
import org.tomitribe.churchkey.Keys;

import java.security.spec.InvalidParameterSpecException;

public class EcKeys {

    /**
     * Despite the appearance that you can supply valid parameters via ECParameterSpec
     * the truth in OpenJDK is that there is a hardcoded list of acceptable parameters.
     * 
     * OpenJDK's CurveDB class will explicitly reject valid ECParameterSpecs
     * if it cannot map it back to an instance of its internal NamedCurve class.
     * This is unfortunate as it doesn't appear anything significant stops these
     * valid ECParameterSpecs from working.
     *
     * Since each JVM version and vendor has a different behavior here, there's
     * no way to reliably exclude these curves from the tests.  So we test them
     * all and ignore the complaint that the curve is unknown.  Hopefully these
     * curves will be added in later JVM versions
     */
    public static Key decode(final byte[] bytes) {
        final Key key;
        try {
            key = Keys.decode(bytes);
        } catch (InvalidPrivateKeySpecException e) {
            Throwable t = getCause(e);
            final boolean unsupported = t instanceof InvalidParameterSpecException && t.getMessage().startsWith("Not a supported curve:");
            Assume.assumeTrue("Test is ignored!", !unsupported);
            throw e;
        }
        return key;
    }

    private static Throwable getCause(final Throwable throwable) {
        if (throwable.getCause() == null) return throwable;
        return getCause(throwable.getCause());
    }
}
