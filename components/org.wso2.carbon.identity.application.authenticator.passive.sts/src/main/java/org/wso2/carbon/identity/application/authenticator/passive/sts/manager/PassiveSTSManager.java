/*
 * Copyright (c) 2005, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.passive.sts.manager;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml1.core.Attribute;
import org.opensaml.saml.saml1.core.AttributeStatement;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.opensaml.saml.saml1.core.Subject;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.passive.sts.exception.PassiveSTSException;
import org.wso2.carbon.identity.application.authenticator.passive.sts.util.PassiveSTSConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

public class PassiveSTSManager {

    private static final Log log = LogFactory.getLog(PassiveSTSManager.class);
    private static Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
    private static boolean bootStrapped = false;
    private X509Credential credential = null;

    public PassiveSTSManager(ExternalIdPConfig externalIdPConfig) throws PassiveSTSException {

        String credentialImplClass = "org.wso2.carbon.identity.application.authenticator.passive.sts.manager.STSAgentKeyStoreCredential";
        try {
            synchronized (this) {
                if (credential == null) {
                    synchronized (this) {
                        STSAgentCredential stsAgentCredential = (STSAgentCredential) Class.forName(credentialImplClass).newInstance();
                        stsAgentCredential.init(externalIdPConfig);
                        this.credential = new X509CredentialImpl(stsAgentCredential);
                    }
                }
            }
        } catch (ClassNotFoundException|InstantiationException|IllegalAccessException e) {
            throw new PassiveSTSException("Error while instantiating SSOAgentCredentialImplClass: " + credentialImplClass, e);
        }
    }

    public static void doBootstrap() {

        /* Initializing the OpenSAML library */
        if (!bootStrapped) {
            try {
                SAMLInitializer.doBootstrap();
                bootStrapped = true;
            } catch (InitializationException e) {
                log.error("Error in bootstrapping the OpenSAML3 library", e);
            }
        }
    }

    /**
     * Returns the redirection URL with the appended SAML2
     * Request message
     *
     * @param request
     * @param loginPage
     * @param contextIdentifier
     * @return redirectionUrl
     * @throws PassiveSTSException
     */
    public String buildRequest(HttpServletRequest request, String loginPage,
                               String contextIdentifier, Map<String, String> authenticationProperties)
            throws PassiveSTSException {

        String replyUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        String action = "wsignin1.0";
        String realm = authenticationProperties.get(PassiveSTSConstants.REALM_ID);
        String redirectUrl = loginPage + "?wa=" + action + "&wreply=" + replyUrl + "&wtrealm=" + realm;
        try {
            redirectUrl = redirectUrl + "&wctx=" + URLEncoder.encode(contextIdentifier, "UTF-8").trim();
        } catch (UnsupportedEncodingException e) {
            throw new PassiveSTSException("Error occurred while url encoding WCTX ", e);
        }
        return redirectUrl;
    }

    /**
     * @param request
     * @param context
     * @throws PassiveSTSException
     */
    public void processResponse(HttpServletRequest request, AuthenticationContext context) throws PassiveSTSException {

        doBootstrap();

        String response = request.getParameter(PassiveSTSConstants.HTTP_PARAM_PASSIVE_STS_RESULT).replaceAll("(\\r|\\n)", "");

        // there is no unmarshaller to unmarshall "RequestSecurityTokenResponseCollection". Therefore retrieve Assertion
        XMLObject xmlObject = unmarshall(response);

        if (xmlObject == null) {
            throw new PassiveSTSException("SAML Assertion not found in the Response");
        }

        // Validate 'Not Before' and 'Not On Or After' Conditions if they are present in the assertion.'
        validateAssertionValidityPeriod(context, xmlObject);
        // Validate for Audience if Audience validation is enabled in IdP Config.
        validateAudienceRestriction(context, xmlObject);
        //Validate the Signature if signature validation is enabled in IdP Config.
        validateSignature(context, xmlObject);

        String subject = null;
        Map<String, String> attributeMap = new HashMap<String, String>();

        if (xmlObject instanceof org.opensaml.saml.saml1.core.Assertion) {
            org.opensaml.saml.saml1.core.Assertion assertion = (org.opensaml.saml.saml1.core.Assertion) xmlObject;
            if (CollectionUtils.isNotEmpty(assertion.getAuthenticationStatements())) {
                Subject subjectElem = assertion.getAuthenticationStatements().get(0).getSubject();

                if (subjectElem != null) {
                    NameIdentifier nameIdentifierElem = subjectElem.getNameIdentifier();

                    if (nameIdentifierElem != null) {
                        subject = nameIdentifierElem.getNameIdentifier();
                    }
                }
            }

            if (CollectionUtils.isNotEmpty(assertion.getAttributeStatements())) {
                if (subject == null) {
                    subject = assertion.getAttributeStatements().get(0).getSubject().getNameIdentifier().getNameIdentifier();
                }

                for (AttributeStatement statement : assertion.getAttributeStatements()) {
                    List<Attribute> attributes = statement.getAttributes();
                    for (Attribute attribute : attributes) {
                        String attributeUri = attribute.getAttributeNamespace();
                        List<XMLObject> xmlObjects = attribute.getAttributeValues();
                        for (XMLObject object : xmlObjects) {
                            String attributeValue = object.getDOM().getTextContent();
                            attributeMap.put(attributeUri, attributeValue);
                        }
                    }
                }
            }
        } else if (xmlObject instanceof org.opensaml.saml.saml2.core.Assertion) {

            org.opensaml.saml.saml2.core.Assertion assertion = (org.opensaml.saml.saml2.core.Assertion) xmlObject;

            if (assertion.getSubject() != null && assertion.getSubject().getNameID() != null) {
                subject = assertion.getSubject().getNameID().getValue();
            }

            for (org.opensaml.saml.saml2.core.AttributeStatement statement : assertion.getAttributeStatements()) {
                List<org.opensaml.saml.saml2.core.Attribute> attributes = statement.getAttributes();
                for (org.opensaml.saml.saml2.core.Attribute attribute : attributes) {
                    String attributeUri = attribute.getName();
                    List<XMLObject> xmlObjects = attribute.getAttributeValues();
                    for (XMLObject object : xmlObjects) {
                        String attributeValue = object.getDOM().getTextContent();
                        attributeMap.put(attributeUri, attributeValue);
                    }
                }
            }
        } else {
            throw new PassiveSTSException("Unknown Security Token. Can process only SAML 2.0 and SAML 1.0 Assertions");
        }

        Map<ClaimMapping, String> claimMappingStringMap = getClaimMappingsMap(attributeMap);
        String isSubjectInClaimsProp = context.getAuthenticatorProperties().get(
                IdentityApplicationConstants.Authenticator.SAML2SSO.IS_USER_ID_IN_CLAIMS);
        if ("true".equalsIgnoreCase(isSubjectInClaimsProp)) {
            subject = FrameworkUtils.getFederatedSubjectFromClaims(
                    context.getExternalIdP().getIdentityProvider(), claimMappingStringMap);
            if (subject == null) {
                log.warn("Subject claim could not be found amongst attribute statements. " +
                        "Defaulting to Name Identifier.");
            }
        }
        if (subject == null) {
            throw new PassiveSTSException("Cannot find federated User Identifier");
        }

        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subject);
        authenticatedUser.setUserAttributes(claimMappingStringMap);
        context.setSubject(authenticatedUser);
    }

    /**
     * @param samlString
     * @param samlString
     * @return
     * @throws PassiveSTSException
     */
    private XMLObject unmarshall(String samlString) throws PassiveSTSException {

        String samlStr = samlString;
        try {
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            ByteArrayInputStream is = new ByteArrayInputStream(samlStr.getBytes(Charset.forName("UTF-8")));
            Document document = docBuilder.parse(is);
            Element element = document.getDocumentElement();

            NodeList nodeList = element.getElementsByTagNameNS("http://docs.oasis-open.org/ws-sx/ws-trust/200512",
                    "RequestedSecurityToken");
            if (nodeList == null || nodeList.getLength() == 0) {
                nodeList = element.getElementsByTagNameNS("http://schemas.xmlsoap.org/ws/2005/02/trust",
                        "RequestedSecurityToken");

                if(nodeList == null || nodeList.getLength() == 0) {
                    throw new PassiveSTSException("Security Token is not found in the Response");
                }

                if (log.isDebugEnabled()) {
                    log.debug("Qualifying 'http://schemas.xmlsoap.org/ws/2005/02/trust' as the Request Security Token Response");
                }
            }

            if (nodeList.getLength() > 1) {
                log.warn("More than one Security Token is found in the Response");
            }

            NodeList SAML2AssertionList = element.getElementsByTagNameNS(SAMLConstants.SAML20_NS, "Assertion");
            if (SAML2AssertionList.getLength() > 1) {
                throw new PassiveSTSException("Invalid Schema for Token Response. Multiple SAML2.0 assertions " +
                                              "detected.");
            }

            NodeList SAML1AssertionList = element.getElementsByTagNameNS(SAMLConstants.SAML1_NS, "Assertion");
            if (SAML1AssertionList.getLength() > 1) {
                throw new PassiveSTSException("Invalid Schema for Token Response. Multiple SAML1.0 assertions " +
                                              "detected.");
            }

            if (SAML2AssertionList.getLength() > 0 && SAML1AssertionList.getLength() > 0) {
                throw new PassiveSTSException("Invalid Schema for Token Response. Multiple SAML assertions detected.");
            }

            Element node = (Element) nodeList.item(0).getFirstChild();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(node);
            return unmarshaller.unmarshall(node);
        } catch (ParserConfigurationException e) {
            throw new PassiveSTSException(PassiveSTSConstants.ERROR_IN_UNMARSHALLING_SAML_REQUEST_FROM_THE_ENCODED_STRING, e);
        } catch (UnmarshallingException e) {
            throw new PassiveSTSException(PassiveSTSConstants.ERROR_IN_UNMARSHALLING_SAML_REQUEST_FROM_THE_ENCODED_STRING, e);
        } catch (SAXException e) {
            throw new PassiveSTSException(PassiveSTSConstants.ERROR_IN_UNMARSHALLING_SAML_REQUEST_FROM_THE_ENCODED_STRING, e);
        } catch (IOException e) {
            throw new PassiveSTSException(PassiveSTSConstants.ERROR_IN_UNMARSHALLING_SAML_REQUEST_FROM_THE_ENCODED_STRING, e);
        }

    }

    /*
     * Process the response and returns the results
     */
    private Map<ClaimMapping, String> getClaimMappingsMap(Map<String, String> userAttributes) {

        Map<ClaimMapping, String> results = new HashMap<ClaimMapping, String>();
        for (Map.Entry<String, String> entry : userAttributes.entrySet()) {
            ClaimMapping claimMapping = new ClaimMapping();

            Claim localClaim = new Claim();
            localClaim.setClaimUri(entry.getKey());

            Claim remoteClaim = new Claim();
            remoteClaim.setClaimUri(entry.getKey());

            claimMapping.setLocalClaim(localClaim);
            claimMapping.setRemoteClaim(remoteClaim);

            results.put(claimMapping, entry.getValue());
        }
        return results;
    }

    /**
     * Validates the 'Not Before' and 'Not On Or After' conditions of the SAML Assertion
     *
     * @param xmlObject parsed SAML entity
     * @throws PassiveSTSException
     */
    private void validateAssertionValidityPeriod(AuthenticationContext context, XMLObject xmlObject)
            throws PassiveSTSException {

        if (log.isDebugEnabled()) {
            log.debug("Validating SAML Assertion's 'Not Before' and 'Not On Or After' conditions.");
        }

        DateTime validFrom = null;
        DateTime validTill = null;

        if (xmlObject instanceof org.opensaml.saml.saml1.core.Assertion) {
            org.opensaml.saml.saml1.core.Assertion saml1Assertion = (org.opensaml.saml.saml1.core.Assertion) xmlObject;
            if (saml1Assertion.getConditions() != null) {
                validFrom = saml1Assertion.getConditions().getNotBefore();
                validTill = saml1Assertion.getConditions().getNotOnOrAfter();
            }
        } else if (xmlObject instanceof org.opensaml.saml.saml2.core.Assertion) {
            org.opensaml.saml.saml2.core.Assertion saml2Assertion = (org.opensaml.saml.saml2.core.Assertion) xmlObject;
            if (saml2Assertion.getConditions() != null) {
                validFrom = saml2Assertion.getConditions().getNotBefore();
                validTill = saml2Assertion.getConditions().getNotOnOrAfter();
            }
        } else {
            throw new PassiveSTSException(
                    "Unknown Security Token. Can process only SAML 1.0 and SAML 2.0 Assertions");
        }

        int clockSkewInSeconds = IdentityUtil.getClockSkewInSeconds();

        if (validFrom != null && validFrom.minusSeconds(clockSkewInSeconds).isAfterNow()) {
            throw new PassiveSTSException("Failed to meet SAML Assertion Condition 'Not Before'");
        }

        if (validTill != null && validTill.plusSeconds(clockSkewInSeconds).isBeforeNow()) {
            throw new PassiveSTSException("Failed to meet SAML Assertion Condition 'Not On Or After'");
        }

        if (validFrom != null && validTill != null && validFrom.isAfter(validTill)) {
            throw new PassiveSTSException(
                    "SAML Assertion Condition 'Not Before' must be less than the value of 'Not On Or After'");
        }
    }

    /**
     * Validates the Audience Restriction of the SAML entity
     *
     * @param context   instance of AuthenticationContext
     * @param xmlObject SAML entity
     * @throws PassiveSTSException
     */
    private void validateAudienceRestriction(AuthenticationContext context, XMLObject xmlObject)
            throws PassiveSTSException {

        boolean validateAudience = true;
        if (context.getAuthenticatorProperties().containsKey(
                IdentityApplicationConstants.Authenticator.PassiveSTS.IS_ENABLE_ASSERTION_AUDIENCE_VALIDATION)) {
            validateAudience = !"false".equalsIgnoreCase(context.getAuthenticatorProperties().get
                    (IdentityApplicationConstants.Authenticator.PassiveSTS
                             .IS_ENABLE_ASSERTION_AUDIENCE_VALIDATION));
        }

        if (validateAudience) {
            if (log.isDebugEnabled()) {
                log.debug("Validating SAML Assertion's Audience Restriction Condition.");
            }

            if (xmlObject instanceof org.opensaml.saml.saml1.core.Assertion) {
                validateAudienceRestriction(context, (org.opensaml.saml.saml1.core.Assertion) xmlObject);
            } else if (xmlObject instanceof org.opensaml.saml.saml2.core.Assertion) {
                validateAudienceRestriction(context, (org.opensaml.saml.saml2.core.Assertion) xmlObject);
            } else {
                throw new PassiveSTSException(
                        "Unknown Security Token. Can process only SAML 1.0 and SAML 2.0 Assertions");
            }
        }
    }

    /**
     * Validates Audience Restriction of SAML 1.0 Assertion
     *
     * @param context        instance of AuthenticationContext
     * @param saml1Assertion SAML 1.0 Assertion element
     * @throws PassiveSTSException
     */
    private void validateAudienceRestriction(AuthenticationContext context,
                                             org.opensaml.saml.saml1.core.Assertion saml1Assertion)
            throws PassiveSTSException {

        if (saml1Assertion.getConditions() != null) {
            List<org.opensaml.saml.saml1.core.AudienceRestrictionCondition> audienceRestrictions =
                    saml1Assertion.getConditions().getAudienceRestrictionConditions();
            if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                /**
                 * Validates if the Passive STS Realm being configured for this relying party is being
                 * included as an Audience under AudienceRestriction
                 */
                String intendedAudience;
                if (context.getAuthenticatorProperties().containsKey(IdentityApplicationConstants.Authenticator
                                                                             .PassiveSTS.REALM_ID)) {
                    intendedAudience = context.getAuthenticatorProperties().get(IdentityApplicationConstants
                                                                                        .Authenticator.PassiveSTS.REALM_ID);
                } else {
                    throw new PassiveSTSException("Cannot validate SAML Assertion Audience Restriction. Failed to" +
                                                  " determine intended audience.");
                }

                for (org.opensaml.saml.saml1.core.AudienceRestrictionCondition audienceRestriction : audienceRestrictions) {
                    if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                        boolean audienceFound = false;
                        for (org.opensaml.saml.saml1.core.Audience audience : audienceRestriction.getAudiences()) {
                            if (intendedAudience.equals(audience.getUri())) {
                                audienceFound = true;
                                break;
                            }
                        }
                        if (!audienceFound) {
                            throw new PassiveSTSException("SAML Assertion Audience Restriction validation failed");
                        }
                    } else {
                        throw new PassiveSTSException("Cannot validate SAML Assertion Audience Restriction. " +
                                                      "Audience Restriction does not specify Audiences.");
                    }
                }
            }
        } else {
            throw new PassiveSTSException("SAML 1.0 Assertion doesn't contain Conditions");
        }
    }

    /**
     * Validates Audience Restriction of SAML 2.0 Assertion
     *
     * @param context        instance of AuthenticationContext
     * @param saml2Assertion SAML 2.0 Assertion element
     * @throws PassiveSTSException
     */
    private void validateAudienceRestriction(AuthenticationContext context,
                                             org.opensaml.saml.saml2.core.Assertion saml2Assertion)
            throws PassiveSTSException {

        if (saml2Assertion.getConditions() != null) {
            List<org.opensaml.saml.saml2.core.AudienceRestriction> audienceRestrictions =
                    saml2Assertion.getConditions().getAudienceRestrictions();
            if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                /**
                 * Validates if the Passive STS Realm being configured for this relying party is being
                 * included as an Audience under AudienceRestriction
                 */
                String intendedAudience;
                if (context.getAuthenticatorProperties().containsKey(IdentityApplicationConstants.Authenticator
                                                                             .PassiveSTS.REALM_ID)) {
                    intendedAudience = context.getAuthenticatorProperties().get(IdentityApplicationConstants
                                                                                        .Authenticator.PassiveSTS.REALM_ID);
                } else {
                    throw new PassiveSTSException("Cannot validate SAML Assertion Audience Restriction. Failed to" +
                                                  " determine intended audience.");
                }

                for (org.opensaml.saml.saml2.core.AudienceRestriction audienceRestriction : audienceRestrictions) {
                    if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                        boolean audienceFound = false;
                        for (org.opensaml.saml.saml2.core.Audience audience : audienceRestriction.getAudiences()) {
                            if (intendedAudience.equals(audience.getAudienceURI())) {
                                audienceFound = true;
                                break;
                            }
                        }
                        if (!audienceFound) {
                            throw new PassiveSTSException("SAML Assertion Audience Restriction validation failed");
                        }
                    } else {
                        throw new PassiveSTSException("Cannot validate SAML Assertion Audience Restriction. " +
                                                      "Audience Restriction does not specify Audiences.");
                    }
                }
            }
        } else {
            throw new PassiveSTSException("SAML 2.0 Assertion doesn't contain Conditions");
        }
    }

    /**
     * Validates the Signature of the SAML entity
     *
     * @param context   instance of AuthenticationContext
     * @param xmlObject SAML entity
     * @throws PassiveSTSException
     */
    private void validateSignature(AuthenticationContext context, XMLObject xmlObject) throws PassiveSTSException {

        boolean validateSignature = true;
        if (context.getAuthenticatorProperties().containsKey(
                IdentityApplicationConstants.Authenticator.PassiveSTS.IS_ENABLE_ASSERTION_SIGNATURE_VALIDATION)) {
            validateSignature = !"false".equalsIgnoreCase(context.getAuthenticatorProperties().get
                    (IdentityApplicationConstants.Authenticator.PassiveSTS
                             .IS_ENABLE_ASSERTION_AUDIENCE_VALIDATION));
        }

        if (validateSignature) {
            if (log.isDebugEnabled()) {
                log.debug("Validating SAML Assertion's Signature.");
            }

            if (xmlObject instanceof SignableSAMLObject) {
                validateSignature(((SignableSAMLObject) xmlObject).getSignature());
            } else {
                throw new PassiveSTSException(
                        "Unknown Security Token. Can process only SAML 1.0 and SAML 2.0 Assertions");
            }
        }
    }

    /**
     * Validates the Signature
     *
     * @param signature signature element
     * @throws PassiveSTSException
     */
    private void validateSignature(Signature signature) throws PassiveSTSException {

        try {
            SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
            signatureProfileValidator.validate(signature);
        } catch (SignatureException e) {
            String msg = "Signature do not confirm to SAML signature profile. Possible XML Signature " +
                         "Wrapping  Attack!";
            AUDIT_LOG.warn(msg);
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new PassiveSTSException(msg, e);
        }

        try {
            SignatureValidator.validate(signature, credential);
        } catch (SignatureException e) {
            throw new PassiveSTSException("Signature validation failed for SAML Assertion", e);
        }
    }
}
