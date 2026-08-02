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

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit tests for the per-IdP test-login enablement flag. Part of the experimental {@code IDP_SAML_TEST} feature.
 */
public class SamlIdentityProviderTestLoginConfigTest {

    @Test
    public void testLoginDisabledByDefault() {
        SAMLIdentityProviderConfig config = new SAMLIdentityProviderConfig();
        Assert.assertFalse(config.isTestLoginEnabled());
    }

    @Test
    public void testLoginEnabledRoundTrips() {
        SAMLIdentityProviderConfig config = new SAMLIdentityProviderConfig();
        config.setTestLoginEnabled(true);
        Assert.assertTrue(config.isTestLoginEnabled());
        Assert.assertEquals("true", config.getConfig().get(SAMLIdentityProviderConfig.TEST_LOGIN_ENABLED));

        config.setTestLoginEnabled(false);
        Assert.assertFalse(config.isTestLoginEnabled());
    }
}
