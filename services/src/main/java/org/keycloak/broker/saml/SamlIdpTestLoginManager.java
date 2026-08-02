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

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import jakarta.ws.rs.core.Response;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.Profile;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

/**
 * Orchestrates the experimental SAML identity provider test login: feature gating, the short-lived result store,
 * capture of the SAML round-trip outcome (success, forwarded IdP error, or protocol-validation failure), and
 * rendering of the terminal pages.
 * <p>
 * The test flow never creates users, links federated identities, runs required actions, or creates authenticated
 * user/client sessions. Part of the experimental {@code IDP_SAML_TEST} feature.
 */
public final class SamlIdpTestLoginManager {

    private static final Logger logger = Logger.getLogger(SamlIdpTestLoginManager.class);

    /** Authentication session note that marks a broker login as a test-login run and carries the test id. */
    public static final String AUTH_NOTE_TEST_LOGIN_ID = "IDP_SAML_TEST_LOGIN_ID";

    /** Default lifespan of a stored test result. */
    public static final int DEFAULT_RESULT_LIFESPAN_SECONDS = 300;

    public static final String TEMPLATE_COMPLETE = "saml-test-complete.ftl";
    public static final String TEMPLATE_FAILED = "saml-test-failed.ftl";

    // Context-data keys used to carry the raw response from SAMLEndpoint to the capturing callback for the
    // success path only. Guarded so that production logins are unaffected.
    private static final String CTX_RAW_RESPONSE = "samlTestRawResponse";
    private static final String CTX_POST_BINDING = "samlTestPostBinding";

    // Request-scoped KeycloakSession attributes used to carry the raw response to the capturing callback on the
    // forwarded-IdP-error path, where no BrokeredIdentityContext exists yet to hang it off. Request scoped and
    // in-memory only, so the raw response is never persisted.
    private static final String ATTR_RAW_RESPONSE = "samlTestRawResponse";
    private static final String ATTR_POST_BINDING = "samlTestPostBinding";

    private SamlIdpTestLoginManager() {
    }

    /**
     * @return {@code true} when the {@code IDP_SAML_TEST} server feature is enabled and the given SAML IdP has test
     * login enabled.
     */
    public static boolean isTestLoginActive(KeycloakSession session, SAMLIdentityProviderConfig config) {
        return Profile.isFeatureEnabled(Profile.Feature.IDP_SAML_TEST)
                && config != null
                && config.isTestLoginEnabled();
    }

    public static boolean isFeatureEnabled() {
        return Profile.isFeatureEnabled(Profile.Feature.IDP_SAML_TEST);
    }

    public static String generateTestId() {
        return SecretGenerator.getInstance().randomString(32);
    }

    public static String getTestLoginId(AuthenticationSessionModel authSession) {
        return authSession == null ? null : authSession.getAuthNote(AUTH_NOTE_TEST_LOGIN_ID);
    }

    // --- result store -------------------------------------------------------------------------------------------

    public static void storePending(KeycloakSession session, String testId, SamlIdpTestLoginResult result) {
        SingleUseObjectProvider store = session.singleUseObjects();
        store.put(SamlIdpTestLoginResult.createKey(testId), result.getRemainingLifespanSeconds(), result.toMap());
    }

    /**
     * Loads a stored result. Returns {@code null} when the test id is unknown, when it belongs to a different realm,
     * or when it was not created for {@code idpAlias} — a test id must only ever be usable through the realm and the
     * identity provider it was issued for.
     */
    public static SamlIdpTestLoginResult getResult(KeycloakSession session, RealmModel realm, String idpAlias,
                                                  String testId) {
        if (testId == null) {
            return null;
        }
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> data = store.get(SamlIdpTestLoginResult.createKey(testId));
        if (data == null) {
            return null;
        }
        SamlIdpTestLoginResult result = SamlIdpTestLoginResult.fromMap(realm, data);
        if (result == null || !Objects.equals(idpAlias, result.getIdpAlias())) {
            return null;
        }
        return result;
    }

    /**
     * Atomically claims the single browser run allowed for this test id. Returns {@code false} when the browser leg
     * has already been started, so re-opening the start URL cannot trigger repeated logins against the identity
     * provider.
     */
    public static boolean claimBrowserRun(KeycloakSession session, String testId, SamlIdpTestLoginResult result) {
        return session.singleUseObjects().putIfAbsent(SamlIdpTestLoginResult.createStartedKey(testId),
                Math.max(1, result.getRemainingLifespanSeconds()));
    }

    /**
     * Resolves the SAML identity provider config for a test-login request, or {@code null} when the request must not
     * be served: the {@code IDP_SAML_TEST} feature is disabled, the alias is unknown or disabled, the provider is not
     * a SAML provider, or test login is not enabled on it. Callers translate {@code null} into {@code 404} so that
     * the reason is never disclosed.
     */
    public static SAMLIdentityProviderConfig resolveTestLoginConfig(KeycloakSession session, String idpAlias) {
        if (!isFeatureEnabled()) {
            return null;
        }
        IdentityProviderModel model = session.identityProviders().getByAlias(idpAlias);
        if (model == null || !model.isEnabled()
                || !SAMLIdentityProviderFactory.PROVIDER_ID.equals(model.getProviderId())) {
            return null;
        }
        SAMLIdentityProviderConfig config = new SAMLIdentityProviderConfig(model);
        return config.isTestLoginEnabled() ? config : null;
    }

    private static void update(KeycloakSession session, String testId, SamlIdpTestLoginResult result) {
        SingleUseObjectProvider store = session.singleUseObjects();
        int lifespan = result.getRemainingLifespanSeconds();
        store.put(SamlIdpTestLoginResult.createKey(testId), lifespan, result.toMap());
    }

    /**
     * Loads a stored result without the identity-provider binding check, for the internal status transitions driven by
     * the broker callback. The alias was already validated when the browser leg was started, and the transition is
     * reached only via an authentication session that carries the test id.
     */
    private static SamlIdpTestLoginResult loadForTransition(KeycloakSession session, String testId) {
        if (testId == null) {
            return null;
        }
        Map<String, String> data = session.singleUseObjects().get(SamlIdpTestLoginResult.createKey(testId));
        return data == null ? null : SamlIdpTestLoginResult.fromMap(session.getContext().getRealm(), data);
    }

    // --- capture (success / error paths) ------------------------------------------------------------------------

    /**
     * Stashes the raw SAML response onto the brokered context so the capturing callback can extract diagnostics on
     * the success path. No-op for non-test sessions, so production logins are unaffected.
     */
    public static void attachRawResponse(AuthenticationSessionModel authSession, BrokeredIdentityContext identity,
                                         String rawSamlResponse, boolean postBinding) {
        if (identity == null || getTestLoginId(authSession) == null) {
            return;
        }
        if (rawSamlResponse != null) {
            identity.getContextData().put(CTX_RAW_RESPONSE, rawSamlResponse);
        }
        identity.getContextData().put(CTX_POST_BINDING, Boolean.toString(postBinding));
    }

    /**
     * Stashes the raw SAML response on the request-scoped session so the capturing callback can extract diagnostics on
     * the forwarded-IdP-error path (where {@code callback.error(...)} is invoked and no brokered context exists yet).
     * No-op for non-test sessions, so production logins are unaffected.
     */
    public static void attachRawResponseForErrorCapture(KeycloakSession session,
                                                        AuthenticationSessionModel authSession,
                                                        String rawSamlResponse, boolean postBinding) {
        if (session == null || getTestLoginId(authSession) == null) {
            return;
        }
        if (rawSamlResponse != null) {
            session.setAttribute(ATTR_RAW_RESPONSE, rawSamlResponse);
        }
        session.setAttribute(ATTR_POST_BINDING, Boolean.toString(postBinding));
    }

    /**
     * Records a failed SAML test login for the forwarded-IdP-error path, using the raw response previously stashed by
     * {@link #attachRawResponseForErrorCapture} so that this path also yields SAML diagnostics.
     */
    public static Response recordForwardedErrorAndRender(KeycloakSession session,
                                                        AuthenticationSessionModel authSession, String message) {
        String rawResponse = session.getAttribute(ATTR_RAW_RESPONSE, String.class);
        boolean postBinding = Boolean.parseBoolean(session.getAttribute(ATTR_POST_BINDING, String.class));
        return recordErrorAndRender(session, authSession, message, rawResponse, postBinding);
    }

    /**
     * Records a successful SAML test login and renders the terminal page. Does NOT create a user/session.
     */
    public static Response recordSuccessAndRender(KeycloakSession session, BrokeredIdentityContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String testId = getTestLoginId(authSession);
        Object rawResponse = context.getContextData().get(CTX_RAW_RESPONSE);
        boolean postBinding = Boolean.parseBoolean(String.valueOf(context.getContextData().get(CTX_POST_BINDING)));

        // Reached only when the broker accepted the response, so the diagnostics are validated.
        String diagnosticsJson = toDiagnosticsJson(
                rawResponse instanceof String raw ? raw : null, postBinding, true);

        SamlIdpTestLoginResult pending = loadForTransition(session, testId);
        if (pending == null || pending.getStatus() != SamlIdpTestLoginResult.Status.PENDING) {
            // The entry expired or already holds a terminal outcome. Never fabricate a replacement: it would have no
            // identity provider alias (making it unreadable through the alias-bound poll endpoint), would extend the
            // original deadline, and would leave captured identity data stranded in the store.
            logger.debug("SAML test login: no pending result to record a success against; rendering only");
            return renderComplete(session, authSession);
        }
        // The test id is effectively a credential for reading the result, so it is never written to the log.
        logger.debugf("SAML test login: success recorded for identity provider '%s'", pending.getIdpAlias());
        update(session, testId, pending.asSuccess(diagnosticsJson));
        return renderComplete(session, authSession);
    }

    /**
     * Records a failed SAML test login (forwarded IdP error or protocol-validation failure) and renders the
     * terminal page.
     */
    public static Response recordErrorAndRender(KeycloakSession session, AuthenticationSessionModel authSession,
                                                String message, String rawSamlResponse, boolean postBinding) {
        String testId = getTestLoginId(authSession);
        // Failure path: the response was rejected, so anything parsed out of it is unvalidated.
        String diagnosticsJson = toDiagnosticsJson(rawSamlResponse, postBinding, false);

        SamlIdpTestLoginResult pending = loadForTransition(session, testId);
        if (pending == null || pending.getStatus() != SamlIdpTestLoginResult.Status.PENDING) {
            // Same reasoning as the success path. This also makes capture idempotent: the artifact binding re-enters
            // Binding.execute, so a failure can be offered twice, the second time without the raw response. The first
            // recorded outcome wins rather than being overwritten with an emptier one.
            logger.debug("SAML test login: no pending result to record an error against; rendering only");
            return renderFailed(session, authSession, message);
        }
        // The test id is effectively a credential for reading the result, so it is never written to the log.
        logger.debugf("SAML test login: error recorded for identity provider '%s' message='%s'",
                pending.getIdpAlias(), message);
        update(session, testId, pending.asError(message, diagnosticsJson));
        return renderFailed(session, authSession, message);
    }

    /**
     * Captures a protocol-validation failure (where {@code SAMLEndpoint} sets {@code event.error(...)} and returns
     * an error page directly, without invoking the broker callback) for a test-login session. Returns the terminal
     * page to render, or {@code null} when nothing was captured (in which case the caller keeps the original
     * response, preserving production behavior).
     */
    public static Response captureValidationFailureIfTestSession(KeycloakSession session,
                                                                 SAMLIdentityProviderConfig config,
                                                                 EventBuilder event, String rawSamlResponse,
                                                                 boolean postBinding, Response originalResponse) {
        if (!isTestLoginActive(session, config) || event == null || event.getEvent() == null) {
            return null;
        }
        String errorCode = event.getEvent().getError();
        if (errorCode == null) {
            // success and forwarded-IdP errors are handled by the capturing callback, not here
            return null;
        }
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        String testId = getTestLoginId(authSession);
        if (testId == null) {
            return null;
        }
        try {
            return recordErrorAndRender(session, authSession, errorCode, rawSamlResponse, postBinding);
        } catch (Exception e) {
            logger.error("SAML test login: failed to capture protocol-validation failure", e);
            return originalResponse;
        }
    }

    /**
     * Parses the raw response into diagnostics.
     *
     * @param validated whether the broker accepted this response. When {@code false} the diagnostics were parsed from
     *                  a response Keycloak rejected, so they are marked unvalidated and must not be read as a
     *                  trustworthy statement about the identity provider.
     */
    private static String toDiagnosticsJson(String rawSamlResponse, boolean postBinding, boolean validated) {
        try {
            SamlTestLoginDiagnostics diagnostics = SamlTestLoginResponseParser.parse(rawSamlResponse, postBinding);
            if (diagnostics == null) {
                return null;
            }
            diagnostics.setSignatureValidated(validated);
            return JsonSerialization.writeValueAsString(diagnostics);
        } catch (Exception e) {
            logger.warnf(e, "SAML test login: could not parse SAML response (%s binding); storing status only",
                    postBinding ? "POST" : "REDIRECT");
            return null;
        }
    }

    // --- rendering ----------------------------------------------------------------------------------------------

    private static Response renderComplete(KeycloakSession session, AuthenticationSessionModel authSession) {
        return session.getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .createForm(TEMPLATE_COMPLETE);
    }

    private static Response renderFailed(KeycloakSession session, AuthenticationSessionModel authSession, String message) {
        return session.getProvider(LoginFormsProvider.class)
                .setAuthenticationSession(authSession)
                .setError(message)
                .createForm(TEMPLATE_FAILED);
    }

    // --- representation for the poll endpoint -------------------------------------------------------------------

    public static Map<String, Object> toStatusRepresentation(String testId, SamlIdpTestLoginResult result) {
        Map<String, Object> rep = new LinkedHashMap<>();
        rep.put("testId", testId);
        SamlIdpTestLoginResult.Status status = result.isExpired() ? SamlIdpTestLoginResult.Status.EXPIRED : result.getStatus();
        rep.put("status", status.name().toLowerCase(Locale.ROOT));
        if (result.getMessage() != null) {
            rep.put("message", result.getMessage());
        }
        if (result.getDiagnosticsJson() != null) {
            try {
                rep.put("saml", JsonSerialization.readValue(result.getDiagnosticsJson(), SamlTestLoginDiagnostics.class));
            } catch (Exception e) {
                // Deliberately does not log the test id, which is effectively a credential for reading the result.
                logger.warnf(e, "SAML test login: could not deserialize stored diagnostics for identity provider '%s'",
                        result.getIdpAlias());
            }
        }
        return rep;
    }
}
