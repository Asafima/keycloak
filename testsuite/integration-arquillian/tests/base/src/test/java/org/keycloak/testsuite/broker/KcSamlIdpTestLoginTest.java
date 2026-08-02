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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.Profile;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.util.SamlClient.Binding;
import org.keycloak.testsuite.util.SamlClientBuilder;
import org.keycloak.util.JsonSerialization;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import static org.keycloak.testsuite.broker.BrokerTestTools.getConsumerRoot;
import static org.keycloak.testsuite.broker.BrokerTestTools.getProviderRoot;
import static org.keycloak.testsuite.util.Matchers.statusCodeIsHC;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * End-to-end integration test for the experimental {@code IDP_SAML_TEST} feature
 * ({@link Profile.Feature#IDP_SAML_TEST}). It seeds a provider realm acting as an external SAML IdP and a consumer
 * realm with a SAML identity provider that has per-IdP test login enabled, then drives the real test-login endpoints
 * against the running server:
 *
 * <ol>
 *   <li>{@code POST /admin/realms/{realm}/identity-provider/instances/{alias}/test-login} &rarr; {@code testId} +
 *       {@code loginUrl} + {@code pollUrl}. Requires the {@code manage-identity-providers} permission.</li>
 *   <li>{@code GET  /realms/{realm}/broker/{alias}/test-login/{testId}/start} &rarr; 302 to the external SAML IdP.
 *       Public, guarded by the opaque test id, because a top-level browser navigation cannot carry a bearer token.</li>
 *   <li>The seeded user logs in at the provider; the SAML response posts back to the broker which records the outcome</li>
 *   <li>{@code GET  /admin/realms/{realm}/identity-provider/instances/{alias}/test-login/{testId}} &rarr;
 *       {@code status=success} with parsed SAML diagnostics. Requires the same permission.</li>
 * </ol>
 *
 * The whole round-trip is driven over HTTP via {@link SamlClientBuilder} (no user/session is ever created by the
 * feature in the consumer realm, so the standard browser harness is not required).
 */
@EnableFeature(value = Profile.Feature.IDP_SAML_TEST)
public class KcSamlIdpTestLoginTest extends AbstractKeycloakTest {

    private static final String CONSUMER_REALM = "saml-test-consumer";
    private static final String IDP_ALIAS = "saml";
    private static final String IDP_ALIAS_OTHER = "saml-other";
    private static final String IDP_ALIAS_NO_TEST = "saml-no-test";
    private static final String USERNAME = "saml-test-user";
    private static final String PASSWORD = "password";

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

    /** Admin REST path of the test-login sub-resource for the given identity provider. */
    private String adminTestLoginUrl(String alias) {
        return getConsumerRoot() + "/auth/admin/realms/" + CONSUMER_REALM
                + "/identity-provider/instances/" + alias + "/test-login";
    }

    private <T extends HttpRequestBase> T withAdminToken(T request) {
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + adminClient.tokenManager().getAccessTokenString());
        return request;
    }

    @Test
    public void testLoginHappyPathReportsSuccessWithSamlDiagnostics() {
        final Map<String, Object> startResult = new HashMap<>();
        final Map<String, Object> pollResult = new HashMap<>();

        SamlClientBuilder builder = new SamlClientBuilder();

        // 1. POST the admin start endpoint, capture testId/loginUrl/pollUrl, then enter the browser flow at loginUrl.
        builder.addStep((client, currentURI, currentResponse, context) -> {
            HttpPost post = withAdminToken(new HttpPost(adminTestLoginUrl(IDP_ALIAS)));
            try (CloseableHttpResponse response = client.execute(post, context)) {
                assertThat(response, statusCodeIsHC(Response.Status.OK));
                startResult.putAll(readJson(response));
            }
            assertThat(startResult.get("testId"), notNullValue());
            assertThat(startResult.get("loginUrl"), notNullValue());
            assertThat(startResult.get("pollUrl"), notNullValue());
            assertThat(startResult.get("expiresIn"), notNullValue());
            // 2. Browser entry: GET .../start. The 302 chain to the external SAML IdP is followed automatically.
            return new HttpGet((String) startResult.get("loginUrl"));
        });

        // 3a. Log in as the seeded user at the provider (the external SAML IdP).
        builder.login().user(USERNAME, PASSWORD).build();

        // 3b. The provider's SAML response auto-posts back to the broker endpoint, which (test-login session)
        //     records the outcome and renders the terminal page instead of creating a user/session.
        builder.processSamlResponse(Binding.POST).build();
        builder.assertResponse(statusCodeIsHC(Response.Status.OK));

        // 4. Poll the admin result endpoint and capture the JSON result.
        builder.addStep((client, currentURI, currentResponse, context) -> {
            HttpGet get = withAdminToken(new HttpGet((String) startResult.get("pollUrl")));
            try (CloseableHttpResponse response = client.execute(get, context)) {
                assertThat(response, statusCodeIsHC(Response.Status.OK));
                pollResult.putAll(readJson(response));
            }
            return null;
        });

        builder.execute();

        assertThat(pollResult.get("testId"), equalTo(startResult.get("testId")));
        assertThat("expected test-login to report success but got: " + pollResult,
                pollResult.get("status"), is("success"));

        @SuppressWarnings("unchecked")
        Map<String, Object> saml = (Map<String, Object>) pollResult.get("saml");
        assertThat("missing parsed SAML diagnostics: " + pollResult, saml, notNullValue());
        assertThat(saml.get("hasAssertion"), is(true));
        assertThat(saml.get("subjectNameId"), is(USERNAME));

        // No user must have been created in the consumer realm by the test login.
        assertThat(adminClient.realm(CONSUMER_REALM).users().search(USERNAME, 0, 10).isEmpty(), is(true));
    }

    @Test
    public void startAndPollRejectUnauthenticatedCallers() {
        // Both admin endpoints must refuse an anonymous caller: the result carries the SAML NameID and attributes.
        new SamlClientBuilder()
                .addStep((client, currentURI, currentResponse, context) -> {
                    try (CloseableHttpResponse response =
                                 client.execute(new HttpPost(adminTestLoginUrl(IDP_ALIAS)), context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.UNAUTHORIZED));
                    }
                    try (CloseableHttpResponse response =
                                 client.execute(new HttpGet(adminTestLoginUrl(IDP_ALIAS) + "/whatever"), context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.UNAUTHORIZED));
                    }
                    return null;
                })
                .execute();
    }

    @Test
    public void testLoginRejectedWhenPerIdpFlagDisabled() {
        // testLoginEnabled=false on this IdP -> the start endpoint must reject the request with 404, even for an admin.
        new SamlClientBuilder()
                .addStep((client, currentURI, currentResponse, context) -> {
                    HttpPost post = withAdminToken(new HttpPost(adminTestLoginUrl(IDP_ALIAS_NO_TEST)));
                    try (CloseableHttpResponse response = client.execute(post, context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.NOT_FOUND));
                    }
                    return null;
                })
                .execute();
    }

    @Test
    public void testIdIsBoundToTheIdentityProviderItWasIssuedFor() {
        // A test id issued for one IdP must not be readable through another IdP that also has test login enabled.
        new SamlClientBuilder()
                .addStep((client, currentURI, currentResponse, context) -> {
                    String testId;
                    HttpPost post = withAdminToken(new HttpPost(adminTestLoginUrl(IDP_ALIAS)));
                    try (CloseableHttpResponse response = client.execute(post, context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.OK));
                        testId = (String) readJson(response).get("testId");
                    }
                    assertThat(testId, notNullValue());

                    // Same realm, same permission, but the wrong identity provider -> 404.
                    HttpGet crossRead = withAdminToken(
                            new HttpGet(adminTestLoginUrl(IDP_ALIAS_OTHER) + "/" + testId));
                    try (CloseableHttpResponse response = client.execute(crossRead, context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.NOT_FOUND));
                    }

                    // The owning identity provider still reads it.
                    HttpGet ownRead = withAdminToken(new HttpGet(adminTestLoginUrl(IDP_ALIAS) + "/" + testId));
                    try (CloseableHttpResponse response = client.execute(ownRead, context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.OK));
                        Map<String, Object> json = readJson(response);
                        assertThat(json.get("status"), is("pending"));
                        assertThat("a pending result must not carry diagnostics", json.get("saml"), nullValue());
                    }
                    return null;
                })
                .execute();
    }

    @Test
    public void browserEntryPointIsSingleUse() {
        // Re-opening the start URL must not fire a second authentication request at the identity provider.
        new SamlClientBuilder()
                .addStep((client, currentURI, currentResponse, context) -> {
                    String loginUrl;
                    HttpPost post = withAdminToken(new HttpPost(adminTestLoginUrl(IDP_ALIAS)));
                    try (CloseableHttpResponse response = client.execute(post, context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.OK));
                        loginUrl = (String) readJson(response).get("loginUrl");
                    }

                    // First use redirects to the external IdP (followed automatically to its login page).
                    try (CloseableHttpResponse response = client.execute(new HttpGet(loginUrl), context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.OK));
                    }
                    // Second use is refused.
                    try (CloseableHttpResponse response = client.execute(new HttpGet(loginUrl), context)) {
                        assertThat(response, statusCodeIsHC(Response.Status.NOT_FOUND));
                    }
                    return null;
                })
                .execute();
    }

    private Map<String, Object> readJson(CloseableHttpResponse response) throws IOException {
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> json = JsonSerialization.readValue(body, Map.class);
        return json;
    }
}
