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

import jakarta.ws.rs.core.Response;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider.AuthenticationCallback;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Wraps the real broker {@link AuthenticationCallback} for SAML identity providers that have the experimental test
 * login enabled. For a test-login session it records the outcome and renders a terminal page <em>instead of</em>
 * creating/linking a user or creating a session. Every other login (production logins, and logins on this IdP that
 * are not test-login runs) is passed straight through to the delegate.
 * <p>
 * Part of the experimental {@code IDP_SAML_TEST} feature.
 */
public class SamlIdpTestLoginCallback implements AuthenticationCallback {

    private final KeycloakSession session;
    private final AuthenticationCallback delegate;

    public SamlIdpTestLoginCallback(KeycloakSession session, AuthenticationCallback delegate) {
        this.session = session;
        this.delegate = delegate;
    }

    @Override
    public Response authenticated(BrokeredIdentityContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (SamlIdpTestLoginManager.getTestLoginId(authSession) == null) {
            return delegate.authenticated(context);
        }
        return SamlIdpTestLoginManager.recordSuccessAndRender(session, context);
    }

    @Override
    public Response error(IdentityProviderModel idpConfig, String message) {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        // Fail closed: without an authentication session there is no way to tell a test run from a real login, and
        // delegating a test run into the real brokering flow would create the user this feature promises not to.
        if (authSession == null) {
            throw new IdentityBrokerException("SAML test login: no authentication session available to record the error");
        }
        if (SamlIdpTestLoginManager.getTestLoginId(authSession) == null) {
            return delegate.error(idpConfig, message);
        }
        return SamlIdpTestLoginManager.recordForwardedErrorAndRender(session, authSession, message);
    }

    @Override
    public AuthenticationSessionModel getAndVerifyAuthenticationSession(String encodedCode) {
        return delegate.getAndVerifyAuthenticationSession(encodedCode);
    }

    @Override
    public Response cancelled(IdentityProviderModel idpConfig) {
        return delegate.cancelled(idpConfig);
    }

    @Override
    public Response retryLogin(UserAuthenticationIdentityProvider<?> identityProvider, AuthenticationSessionModel authSession) {
        return delegate.retryLogin(identityProvider, authSession);
    }
}
