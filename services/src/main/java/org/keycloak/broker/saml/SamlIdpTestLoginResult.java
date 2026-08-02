/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.broker.saml;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.common.util.Time;
import org.keycloak.models.RealmModel;

/**
 * Short-lived result of an experimental SAML identity provider test login. It is stored in the
 * {@link org.keycloak.models.SingleUseObjectProvider single-use object store} (the same TTL-bound, cluster-aware
 * mechanism used for OAuth 2.0 device codes), keyed by a high-entropy opaque test id.
 * <p>
 * The model serializes to/from a flat {@code Map<String, String>}. The SAML diagnostics (see
 * {@link SamlTestLoginDiagnostics}) are stored as a JSON string and never include the raw SAML response.
 * <p>
 * Part of the experimental {@code IDP_SAML_TEST} feature.
 */
public class SamlIdpTestLoginResult {

    public enum Status {
        PENDING,
        SUCCESS,
        ERROR,
        EXPIRED
    }

    private static final String KEY_PREFIX = "idp.saml.test.";

    private static final String REALM_ID = "rid";
    private static final String IDP_ALIAS = "alias";
    private static final String STATUS = "status";
    private static final String MESSAGE = "message";
    private static final String EXPIRATION = "exp";
    private static final String DIAGNOSTICS_JSON = "saml";

    private final String realmId;
    private final String idpAlias;
    private final Status status;
    private final String message;
    private final int expiration;
    private final String diagnosticsJson;

    public SamlIdpTestLoginResult(String realmId, String idpAlias, Status status, String message, int expiration,
                                  String diagnosticsJson) {
        this.realmId = realmId;
        this.idpAlias = idpAlias;
        this.status = status;
        this.message = message;
        this.expiration = expiration;
        this.diagnosticsJson = diagnosticsJson;
    }

    public static SamlIdpTestLoginResult pending(RealmModel realm, String idpAlias, int expiresInSeconds) {
        return new SamlIdpTestLoginResult(realm.getId(), idpAlias, Status.PENDING, null,
                Time.currentTime() + expiresInSeconds, null);
    }

    public SamlIdpTestLoginResult asSuccess(String diagnosticsJson) {
        return new SamlIdpTestLoginResult(realmId, idpAlias, Status.SUCCESS, null, expiration, diagnosticsJson);
    }

    public SamlIdpTestLoginResult asError(String message, String diagnosticsJson) {
        return new SamlIdpTestLoginResult(realmId, idpAlias, Status.ERROR, message, expiration, diagnosticsJson);
    }

    public static String createKey(String testId) {
        return KEY_PREFIX + testId;
    }

    /**
     * Key of the marker that records that the browser leg for this test id has already been started. Stored
     * separately from the result so that claiming it can be done atomically (and therefore cluster-safely) with
     * {@link org.keycloak.models.SingleUseObjectProvider#putIfAbsent(String, long)}, making the browser entry point
     * single-use.
     */
    public static String createStartedKey(String testId) {
        return KEY_PREFIX + testId + ".started";
    }

    public static SamlIdpTestLoginResult fromMap(RealmModel realm, Map<String, String> data) {
        if (data == null || !realm.getId().equals(data.get(REALM_ID))) {
            return null;
        }
        Status status;
        try {
            status = Status.valueOf(data.getOrDefault(STATUS, Status.PENDING.name()));
        } catch (IllegalArgumentException e) {
            status = Status.PENDING;
        }
        int expiration = 0;
        try {
            expiration = Integer.parseInt(data.getOrDefault(EXPIRATION, "0"));
        } catch (NumberFormatException e) {
            // keep 0 -> treated as expired
        }
        return new SamlIdpTestLoginResult(data.get(REALM_ID), data.get(IDP_ALIAS), status, data.get(MESSAGE),
                expiration, data.get(DIAGNOSTICS_JSON));
    }

    public Map<String, String> toMap() {
        Map<String, String> result = new HashMap<>();
        result.put(REALM_ID, realmId);
        if (idpAlias != null) {
            result.put(IDP_ALIAS, idpAlias);
        }
        result.put(STATUS, status.name());
        result.put(EXPIRATION, String.valueOf(expiration));
        if (message != null) {
            result.put(MESSAGE, message);
        }
        if (diagnosticsJson != null) {
            result.put(DIAGNOSTICS_JSON, diagnosticsJson);
        }
        return result;
    }

    public String getRealmId() {
        return realmId;
    }

    public String getIdpAlias() {
        return idpAlias;
    }

    public Status getStatus() {
        return status;
    }

    public String getMessage() {
        return message;
    }

    public int getExpiration() {
        return expiration;
    }

    public String getDiagnosticsJson() {
        return diagnosticsJson;
    }

    public boolean isExpired() {
        return expiration - Time.currentTime() < 0;
    }

    public int getRemainingLifespanSeconds() {
        return Math.max(0, expiration - Time.currentTime());
    }
}
