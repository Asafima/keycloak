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

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.AudienceRestrictionType;
import org.keycloak.dom.saml.v2.assertion.BaseIDAbstractType;
import org.keycloak.dom.saml.v2.assertion.ConditionAbstractType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.saml.SAMLRequestParser;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Parses a raw SAML response into a {@link SamlTestLoginDiagnostics} view containing only safe, non-sensitive
 * fields. The raw SAML XML is never retained. Long values are truncated.
 * <p>
 * Part of the experimental {@code IDP_SAML_TEST} feature.
 */
final class SamlTestLoginResponseParser {

    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    static final int MAX_VALUE_LENGTH = 512;

    private SamlTestLoginResponseParser() {
    }

    static SamlTestLoginDiagnostics parse(String rawSamlResponse, boolean postBinding) {
        if (rawSamlResponse == null || rawSamlResponse.isBlank()) {
            return null;
        }
        SAMLDocumentHolder holder = postBinding
                ? SAMLRequestParser.parseResponsePostBinding(rawSamlResponse)
                : SAMLRequestParser.parseResponseRedirectBinding(rawSamlResponse);
        if (holder == null || !(holder.getSamlObject() instanceof ResponseType responseType)) {
            return null;
        }

        SamlTestLoginDiagnostics diagnostics = new SamlTestLoginDiagnostics();
        diagnostics.setIssuer(truncate(responseType.getIssuer() == null ? null : responseType.getIssuer().getValue()));
        diagnostics.setDestination(truncate(responseType.getDestination()));
        if (responseType.getStatus() != null) {
            if (responseType.getStatus().getStatusCode() != null
                    && responseType.getStatus().getStatusCode().getValue() != null) {
                diagnostics.setStatusCode(truncate(responseType.getStatus().getStatusCode().getValue().toString()));
            }
            diagnostics.setStatusMessage(truncate(responseType.getStatus().getStatusMessage()));
        }

        AssertionType assertion = getFirstAssertion(responseType);
        diagnostics.setHasAssertion(assertion != null);
        diagnostics.setEncrypted(assertion == null && hasEncryptedAssertion(responseType));

        if (assertion != null) {
            diagnostics.setAssertionIssuer(truncate(assertion.getIssuer() == null ? null : assertion.getIssuer().getValue()));
            diagnostics.setAudiences(audiences(assertion));
            NameIDType nameId = getSubjectNameId(assertion);
            if (nameId != null) {
                diagnostics.setSubjectNameId(truncate(nameId.getValue()));
                diagnostics.setSubjectNameIdFormat(truncate(nameId.getFormat() == null ? null : nameId.getFormat().toString()));
            }
            diagnostics.setAttributes(getAttributes(assertion));
        }

        Document doc = holder.getSamlDocument();
        // Presence of a signature element only. Validity is reported separately, by the caller, because it depends on
        // whether the broker accepted the response rather than on anything visible in the document.
        diagnostics.setResponseSignaturePresent(doc != null && hasDirectChildSignature(doc.getDocumentElement()));
        diagnostics.setAssertionSignaturePresent(doc != null && anyAssertionSigned(doc));

        return diagnostics;
    }

    private static AssertionType getFirstAssertion(ResponseType responseType) {
        if (responseType.getAssertions() == null) {
            return null;
        }
        for (ResponseType.RTChoiceType choice : responseType.getAssertions()) {
            if (choice.getAssertion() != null) {
                return choice.getAssertion();
            }
        }
        return null;
    }

    private static boolean hasEncryptedAssertion(ResponseType responseType) {
        if (responseType.getAssertions() == null) {
            return false;
        }
        for (ResponseType.RTChoiceType choice : responseType.getAssertions()) {
            if (choice.getEncryptedAssertion() != null) {
                return true;
            }
        }
        return false;
    }

    private static List<String> audiences(AssertionType assertion) {
        List<String> audiences = new ArrayList<>();
        if (assertion.getConditions() == null || assertion.getConditions().getConditions() == null) {
            return audiences;
        }
        for (ConditionAbstractType condition : assertion.getConditions().getConditions()) {
            if (condition instanceof AudienceRestrictionType audienceRestriction
                    && audienceRestriction.getAudience() != null) {
                for (URI audience : audienceRestriction.getAudience()) {
                    if (audience != null) {
                        audiences.add(truncate(audience.toString()));
                    }
                }
            }
        }
        return audiences;
    }

    private static NameIDType getSubjectNameId(AssertionType assertion) {
        SubjectType subject = assertion.getSubject();
        if (subject == null || subject.getSubType() == null) {
            return null;
        }
        BaseIDAbstractType baseId = subject.getSubType().getBaseID();
        return baseId instanceof NameIDType nameId ? nameId : null;
    }

    private static List<SamlTestLoginDiagnostics.Attribute> getAttributes(AssertionType assertion) {
        List<SamlTestLoginDiagnostics.Attribute> result = new ArrayList<>();
        for (AttributeStatementType statement : assertion.getAttributeStatements()) {
            for (AttributeStatementType.ASTChoiceType choice : statement.getAttributes()) {
                AttributeType attribute = choice.getAttribute();
                if (attribute == null) {
                    continue;
                }
                List<String> values = new ArrayList<>();
                for (Object value : attribute.getAttributeValue()) {
                    if (value != null) {
                        values.add(truncate(String.valueOf(value)));
                    }
                }
                result.add(new SamlTestLoginDiagnostics.Attribute(
                        truncate(attribute.getName()), truncate(attribute.getFriendlyName()), values));
            }
        }
        return result;
    }

    private static boolean anyAssertionSigned(Document doc) {
        NodeList assertions = doc.getElementsByTagNameNS(SAML_ASSERTION_NS, "Assertion");
        for (int i = 0; i < assertions.getLength(); i++) {
            if (assertions.item(i) instanceof Element assertionElement && hasDirectChildSignature(assertionElement)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasDirectChildSignature(Element element) {
        if (element == null) {
            return false;
        }
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE
                    && "Signature".equals(child.getLocalName())
                    && XMLDSIG_NS.equals(child.getNamespaceURI())) {
                return true;
            }
        }
        return false;
    }

    private static String truncate(String value) {
        if (value == null || value.length() <= MAX_VALUE_LENGTH) {
            return value;
        }
        return value.substring(0, MAX_VALUE_LENGTH - 3) + "...";
    }
}
