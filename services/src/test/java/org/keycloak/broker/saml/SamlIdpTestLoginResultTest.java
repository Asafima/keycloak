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

import java.util.Map;

import org.keycloak.common.util.Time;

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit tests for the short-lived SAML test-login result model. Part of the experimental {@code IDP_SAML_TEST}
 * feature. These tests avoid any mocking framework and exercise the (de)serialization, status transitions, and
 * expiry logic in isolation.
 */
public class SamlIdpTestLoginResultTest {

    @Test
    public void createKeyIsPrefixed() {
        Assert.assertEquals("idp.saml.test.abc", SamlIdpTestLoginResult.createKey("abc"));
    }

    @Test
    public void startedMarkerKeyIsDistinctFromTheResultKey() {
        // The single-use marker that makes the browser leg non-replayable must not collide with the result entry.
        Assert.assertEquals("idp.saml.test.abc.started", SamlIdpTestLoginResult.createStartedKey("abc"));
        Assert.assertNotEquals(SamlIdpTestLoginResult.createKey("abc"),
                SamlIdpTestLoginResult.createStartedKey("abc"));
    }

    @Test
    public void pendingResultSerializesStatusRealmAndAlias() {
        int exp = Time.currentTime() + 300;
        SamlIdpTestLoginResult result = new SamlIdpTestLoginResult("realm-id", "saml-idp",
                SamlIdpTestLoginResult.Status.PENDING, null, exp, null);

        Map<String, String> map = result.toMap();

        Assert.assertEquals("realm-id", map.get("rid"));
        Assert.assertEquals("saml-idp", map.get("alias"));
        Assert.assertEquals("PENDING", map.get("status"));
        Assert.assertEquals(String.valueOf(exp), map.get("exp"));
        Assert.assertFalse(map.containsKey("message"));
        Assert.assertFalse(map.containsKey("saml"));
    }

    @Test
    public void successTransitionStoresDiagnosticsAndKeepsExpiration() {
        int exp = Time.currentTime() + 300;
        SamlIdpTestLoginResult pending = new SamlIdpTestLoginResult("realm-id", "saml-idp",
                SamlIdpTestLoginResult.Status.PENDING, null, exp, null);

        SamlIdpTestLoginResult success = pending.asSuccess("{\"issuer\":\"x\"}");

        Assert.assertEquals(SamlIdpTestLoginResult.Status.SUCCESS, success.getStatus());
        Assert.assertEquals("{\"issuer\":\"x\"}", success.getDiagnosticsJson());
        Assert.assertEquals(exp, success.getExpiration());
        Assert.assertEquals("saml-idp", success.getIdpAlias());
        Assert.assertNull(success.getMessage());
    }

    @Test
    public void errorTransitionStoresMessageAndDiagnostics() {
        int exp = Time.currentTime() + 300;
        SamlIdpTestLoginResult pending = new SamlIdpTestLoginResult("realm-id", "saml-idp",
                SamlIdpTestLoginResult.Status.PENDING, null, exp, null);

        SamlIdpTestLoginResult error = pending.asError("invalid_signature", "{\"statusCode\":\"x\"}");
        Map<String, String> map = error.toMap();

        Assert.assertEquals(SamlIdpTestLoginResult.Status.ERROR, error.getStatus());
        Assert.assertEquals("invalid_signature", map.get("message"));
        Assert.assertEquals("{\"statusCode\":\"x\"}", map.get("saml"));
    }

    @Test
    public void expiredExpirationIsExpiredAndHasNoRemainingLifespan() {
        SamlIdpTestLoginResult result = new SamlIdpTestLoginResult("realm-id", "saml-idp",
                SamlIdpTestLoginResult.Status.PENDING, null, Time.currentTime() - 10, null);

        Assert.assertTrue(result.isExpired());
        Assert.assertEquals(0, result.getRemainingLifespanSeconds());
    }

    @Test
    public void futureExpirationIsNotExpired() {
        SamlIdpTestLoginResult result = new SamlIdpTestLoginResult("realm-id", "saml-idp",
                SamlIdpTestLoginResult.Status.PENDING, null, Time.currentTime() + 120, null);

        Assert.assertFalse(result.isExpired());
        Assert.assertTrue(result.getRemainingLifespanSeconds() > 0);
    }
}
