/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.fido.server.endpoint;

import java.util.Objects;

public class ServerAuthenticatorAttestationResponse implements ServerAuthenticatorResponse {

    private String clientDataJSON;
    private String attestationObject;

    public ServerAuthenticatorAttestationResponse(String clientDataJSON, String attestationObject) {
        this.clientDataJSON = clientDataJSON;
        this.attestationObject = attestationObject;
    }

    public ServerAuthenticatorAttestationResponse() {
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public String getAttestationObject() {
        return attestationObject;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerAuthenticatorAttestationResponse that = (ServerAuthenticatorAttestationResponse) o;
        return Objects.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(attestationObject, that.attestationObject);
    }

    @Override
    public int hashCode() {

        return Objects.hash(clientDataJSON, attestationObject);
    }
}
