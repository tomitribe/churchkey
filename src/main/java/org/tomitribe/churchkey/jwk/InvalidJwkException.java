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
package org.tomitribe.churchkey.jwk;

public class InvalidJwkException extends IllegalArgumentException {

    private final String jwk;

    public InvalidJwkException(final String message, final Throwable cause, final String jwk) {
        super(message, cause);
        this.jwk = jwk;
    }

    public InvalidJwkException(final Throwable cause, final String jwk) {
        super(cause);
        this.jwk = jwk;
    }

    @Override
    public String getMessage() {
        return String.format("Invalid JWK: %s%n%s", super.getMessage(), jwk);
    }
}
