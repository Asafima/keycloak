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
package org.keycloak.testsuite.broker;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.Profile;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.util.SamlClientBuilder;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.junit.Test;

import static org.keycloak.testsuite.broker.BrokerTestTools.getConsumerRoot;
import static org.keycloak.testsuite.broker.BrokerTestTools.getProviderRoot;
import static org.keycloak.testsuite.util.Matchers.statusCodeIsHC;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Counterpart to {@link KcSamlIdpTestLoginTest}, deliberately WITHOUT {@code @EnableFeature}, so that
 * {@link Profile.Feature#IDP_SAML_TEST} is disabled exactly as it is by default.
 * <p>
 * This asserts the central claim of the experimental feature: with the server feature off, none of the test-login
 * endpoints exist, even for an administrator and even for an identity provider whose {@code testLoginEnabled} config
 * flag is set to {@code true}.
 */
public class KcSamlIdpTestLoginDisabledTest extends AbstractKeycloakTest {

    private static final String CONSUMER_REALM = "saml-test-consumer";
    private static final String IDP_ALIAS = "saml";

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        testRealms.add(loadRealmWithRoots("/broker/saml-idp-test-login/provider-realm.json"));
        testRealms.add(loadRealmWithRoots("/broker/saml-idp-test-login/consumer-realm.json"));
    }

    private RealmRepresentation loadRealmWithRoots(String resourcePath) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            assertThat("Missing realm export resource: " + resourcePath, is, notNullValue());
            String json = new String(is.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("PROVIDER_ROOT", getProviderRoot())
                    .replace("CONSUMER_ROOT", getConsumerRoot());
            return JsonSerialization.readValue(json, RealmRepresentation.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load realm export: " + resourcePath, e);
        }
    }

    private String adminTestLoginUrl(String alias) {
        return getConsumerRoot() + "/auth/admin/realms/" + CONSUMER_REALM
                + "/identity-provider/instances/" + alias + "/test-login";
    }

    private String brokerStartUrl(String alias, String testId) {
        return getConsumerRoot() + "/auth/realms/" + CONSUMER_REALM + "/broker/" + alias
                + "/test-login/" + testId + "/start";
    }

    private <T extends HttpRequestBase> T withAdminToken(T request) {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + adminClient.tokenManager().getAccessTokenString());
        return request;
    }

    @Test
    public void allTestLoginEndpointsAreAbsentWhenFeatureDisabled() {
        // testLoginEnabled=true on this IdP in the fixture, so the server feature flag is the only thing gating these.
        new SamlClientBuilder()
                .addStep((client, currentURI, currentResponse, context) -> {
                    HttpPost start = withAdminToken(new HttpPost(adminTestLoginUrl(IDP_ALIAS)));
                    try (CloseableHttpResponse response = client.execute(start, context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.NOT_FOUND));
                    }

                    HttpGet poll = withAdminToken(new HttpGet(adminTestLoginUrl(IDP_ALIAS) + "/some-test-id"));
                    try (CloseableHttpResponse response = client.execute(poll, context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.NOT_FOUND));
                    }

                    try (CloseableHttpResponse response =
                                 client.execute(new HttpGet(brokerStartUrl(IDP_ALIAS, "some-test-id")), context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.NOT_FOUND));
                    }
                    return null;
                })
                .execute();
    }

    // Note: there is deliberately no "normal brokered login still works" test here. Every other KcSaml*Test in this
    // package already runs with IDP_SAML_TEST disabled, so the untouched production path is covered by the existing
    // suite rather than by a duplicate of it.
}
