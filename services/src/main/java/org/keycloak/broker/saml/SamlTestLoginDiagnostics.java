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

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Safe, non-sensitive diagnostic view of a SAML response captured during an experimental SAML identity provider
 * test login. It intentionally never carries the raw SAML XML and only exposes fields useful to diagnose a SAML
 * configuration problem.
 * <p>
 * This is part of the experimental {@code IDP_SAML_TEST} feature.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class SamlTestLoginDiagnostics {

    private String issuer;
    private String destination;
    private String statusCode;
    private String statusMessage;
    private boolean encrypted;
    private boolean hasAssertion;
    private String assertionIssuer;
    private List<String> audiences = new ArrayList<>();
    private String subjectNameId;
    private String subjectNameIdFormat;
    private List<Attribute> attributes = new ArrayList<>();
    private boolean responseSignaturePresent;
    private boolean assertionSignaturePresent;
    private boolean signatureValidated;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(String statusCode) {
        this.statusCode = statusCode;
    }

    public String getStatusMessage() {
        return statusMessage;
    }

    public void setStatusMessage(String statusMessage) {
        this.statusMessage = statusMessage;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public void setEncrypted(boolean encrypted) {
        this.encrypted = encrypted;
    }

    public boolean isHasAssertion() {
        return hasAssertion;
    }

    public void setHasAssertion(boolean hasAssertion) {
        this.hasAssertion = hasAssertion;
    }

    public String getAssertionIssuer() {
        return assertionIssuer;
    }

    public void setAssertionIssuer(String assertionIssuer) {
        this.assertionIssuer = assertionIssuer;
    }

    public List<String> getAudiences() {
        return audiences;
    }

    public void setAudiences(List<String> audiences) {
        this.audiences = audiences;
    }

    public String getSubjectNameId() {
        return subjectNameId;
    }

    public void setSubjectNameId(String subjectNameId) {
        this.subjectNameId = subjectNameId;
    }

    public String getSubjectNameIdFormat() {
        return subjectNameIdFormat;
    }

    public void setSubjectNameIdFormat(String subjectNameIdFormat) {
        this.subjectNameIdFormat = subjectNameIdFormat;
    }

    public List<Attribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<Attribute> attributes) {
        this.attributes = attributes;
    }

    /**
     * Whether a signature element is present on the response. This reports presence only; it says nothing about
     * whether the signature is valid. See {@link #isSignatureValidated()}.
     */
    public boolean isResponseSignaturePresent() {
        return responseSignaturePresent;
    }

    public void setResponseSignaturePresent(boolean responseSignaturePresent) {
        this.responseSignaturePresent = responseSignaturePresent;
    }

    /**
     * Whether a signature element is present on any assertion. Presence only, not validity.
     */
    public boolean isAssertionSignaturePresent() {
        return assertionSignaturePresent;
    }

    public void setAssertionSignaturePresent(boolean assertionSignaturePresent) {
        this.assertionSignaturePresent = assertionSignaturePresent;
    }

    /**
     * Whether the broker accepted this response, meaning every check the identity provider configuration asks for
     * (including signature validation, when enabled) passed. When {@code false}, every other field on this object was
     * parsed from a response that Keycloak rejected, so the values are attacker-influenced and must not be trusted as
     * a statement about the identity provider.
     */
    public boolean isSignatureValidated() {
        return signatureValidated;
    }

    public void setSignatureValidated(boolean signatureValidated) {
        this.signatureValidated = signatureValidated;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Attribute {

        private String name;
        private String friendlyName;
        private List<String> values = new ArrayList<>();

        public Attribute() {
        }

        public Attribute(String name, String friendlyName, List<String> values) {
            this.name = name;
            this.friendlyName = friendlyName;
            this.values = values;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getFriendlyName() {
            return friendlyName;
        }

        public void setFriendlyName(String friendlyName) {
            this.friendlyName = friendlyName;
        }

        public List<String> getValues() {
            return values;
        }

        public void setValues(List<String> values) {
            this.values = values;
        }
    }
}
