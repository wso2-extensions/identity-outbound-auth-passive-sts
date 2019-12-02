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

package org.wso2.carbon.identity.application.authenticator.passive.sts;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.passive.sts.exception.PassiveSTSException;
import org.wso2.carbon.identity.application.authenticator.passive.sts.manager.PassiveSTSManager;
import org.wso2.carbon.identity.application.authenticator.passive.sts.util.PassiveSTSConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class PassiveSTSAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -8097512332218044090L;

    private static final Log log = LogFactory.getLog(PassiveSTSAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside canHandle()");
        }

        if (request.getParameter(PassiveSTSConstants.HTTP_PARAM_PASSIVE_STS_RESULT) != null
                || request.getParameter(PassiveSTSConstants.HTTP_PARAM_PASSIVE_STS_LOGOUT) != null) {
            return true;
        }

        return false;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {


        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
        String idpURL = context.getAuthenticatorProperties().get(IdentityApplicationConstants.Authenticator.PassiveSTS.IDENTITY_PROVIDER_URL);
        String loginPage;

        try {
            loginPage = new PassiveSTSManager(externalIdPConfig).buildRequest(request, idpURL, context.getContextIdentifier(), context.getAuthenticatorProperties());
        } catch (PassiveSTSException e) {
            log.error("Exception while building the WS-Federation request", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }

        try {
            String domain = request.getParameter("domain");

            if (domain != null) {
                loginPage = loginPage + "&fidp=" + domain;
            }

            Map<String, String> authenticatorProperties = context
                    .getAuthenticatorProperties();

            if (authenticatorProperties != null) {
                String queryString = authenticatorProperties
                        .get(FrameworkConstants.QUERY_PARAMS);
                if (queryString != null) {
                    if (!queryString.startsWith("&")) {
                        loginPage = loginPage + "&" + queryString;
                    } else {
                        loginPage = loginPage + queryString;
                    }
                }
            }

            response.sendRedirect(loginPage);
        } catch (IOException e) {
            log.error("Exception while sending to the login page", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();

        if (request.getParameter(PassiveSTSConstants.HTTP_PARAM_PASSIVE_STS_RESULT) != null) {
            try {
                new PassiveSTSManager(externalIdPConfig).processResponse(request, context);
            } catch (PassiveSTSException e) {
                log.error("Exception while processing WS-Federation response", e);
                throw new AuthenticationFailedException(e.getMessage(), context.getSubject(), e);
            }
        } else {
            log.error("wresult can not be found in request");
            throw new AuthenticationFailedException("wresult can not be found in request", context.getSubject());
        }

    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        if (log.isTraceEnabled()) {
            log.trace("Inside getContextIdentifier()");
        }

        String identifier = request.getParameter("sessionDataKey");

        if (identifier == null) {
            if (log.isDebugEnabled()) {
                log.debug("Context identifier: " + identifier);
            }
            identifier = request.getParameter("wctx");

            if (identifier != null) {
                // TODO SHOULD ensure that the value has not been tampered with by using a checksum, a pseudo-random value, or similar means.
                try {
                    return URLDecoder.decode(identifier, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    log.error("Exception while URL decoding the Relay State", e);
                }
            }

            identifier = request.getParameter(PassiveSTSConstants.HTTP_PARAM_PASSIVE_STS_LOGOUT);

            if (identifier != null) {
                if (log.isDebugEnabled()) {
                    log.debug("passive sts logout parameter: " + identifier);
                }
                try {
                    return URLDecoder.decode(identifier, "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    log.error("Exception while URL decoding the Relay State", e);
                }
            }
        }

        return identifier;
    }

    @Override
    public String getFriendlyName() {
        return "passivests";
    }

    @Override
    public String getName() {
        return PassiveSTSConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws LogoutFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String idpURL = authenticatorProperties
                .get(IdentityApplicationConstants.Authenticator.PassiveSTS.IDENTITY_PROVIDER_URL);
        String logOutPage;

        try {
            String callbackUrl = authenticatorProperties.get(PassiveSTSConstants.PASSIVE_STS_CALL_BACK_URL);
            if (StringUtils.isEmpty(callbackUrl)) {
                callbackUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
            }
            String replyUrl = callbackUrl + "?" + PassiveSTSConstants.HTTP_PARAM_PASSIVE_STS_LOGOUT + "=" + context
                    .getContextIdentifier();
            logOutPage = buildLogoutRequest(idpURL, context.getContextIdentifier(),
                    context.getAuthenticatorProperties(), PassiveSTSConstants.HTTP_PARAM_PASSIVE_STS_WSIGNOUT,
                    replyUrl);
        } catch (PassiveSTSException e) {
            throw new LogoutFailedException("Exception while building the WS-Federation logout request", e);
        }

        try {
            response.sendRedirect(logOutPage);
        } catch (IOException e) {
            throw new LogoutFailedException("Exception while sending to the logout page", e);
        }
    }

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property realm = new Property();
        realm.setName(IdentityApplicationConstants.Authenticator.PassiveSTS.REALM_ID);
        realm.setDisplayName("Passive STS Realm");
        realm.setRequired(true);
        realm.setDescription("Enter passive sts realm value");
        realm.setType("string");
        realm.setDisplayOrder(1);
        configProperties.add(realm);

        Property url = new Property();
        url.setName(IdentityApplicationConstants.Authenticator.PassiveSTS.REALM_ID);
        url.setDisplayName("Passive STS URL");
        url.setRequired(true);
        url.setDescription("Enter passive sts URL value");
        url.setType("string");
        url.setDisplayOrder(2);
        configProperties.add(url);

        Property userIdLocation = new Property();
        userIdLocation.setName(IdentityApplicationConstants.Authenticator.PassiveSTS.IS_USER_ID_IN_CLAIMS);
        userIdLocation.setDisplayName("Passive STS User ID Location");
        userIdLocation.setRequired(false);
        userIdLocation.setDescription("Specifies the location to find the user identifier in the SAML2 assertion");
        userIdLocation.setType("boolean");
        userIdLocation.setDisplayOrder(3);
        configProperties.add(userIdLocation);

        Property validateAssertionSig = new Property();
        validateAssertionSig.setName(IdentityApplicationConstants.Authenticator.PassiveSTS
                .IS_ENABLE_ASSERTION_SIGNATURE_VALIDATION);
        validateAssertionSig.setDisplayName("Enable SAML Assertion Signature Validation");
        validateAssertionSig.setRequired(false);
        validateAssertionSig.setDescription("Specifies if SAML Assertion Signature should be validated");
        validateAssertionSig.setType("boolean");
        validateAssertionSig.setDefaultValue("true");
        validateAssertionSig.setDisplayOrder(4);
        configProperties.add(validateAssertionSig);

        Property validateAssertionAud = new Property();
        validateAssertionAud.setName(IdentityApplicationConstants.Authenticator.PassiveSTS
                .IS_ENABLE_ASSERTION_AUDIENCE_VALIDATION);
        validateAssertionAud.setDisplayName("Enable SAML Assertion Audience Validation");
        validateAssertionAud.setRequired(false);
        validateAssertionAud.setDescription("Specifies if SAML Assertion Audience should be validated");
        validateAssertionAud.setType("boolean");
        validateAssertionSig.setDefaultValue("true");
        validateAssertionAud.setDisplayOrder(5);
        configProperties.add(validateAssertionAud);

        Property queryParams = new Property();
        queryParams.setName("commonAuthQueryParams");
        queryParams.setDisplayName("Additional Query Parameters");
        queryParams.setRequired(false);
        queryParams.setDescription("Additional query parameters. e.g: paramName1=value1");
        queryParams.setType("string");
        queryParams.setDisplayOrder(6);
        configProperties.add(queryParams);

        return configProperties;
    }

    private String buildLogoutRequest(String loginPage, String contextIdentifier,
            Map<String, String> authenticationProperties, String action, String replyUrl) throws PassiveSTSException {
        String realm = authenticationProperties.get(PassiveSTSConstants.REALM_ID);
        String redirectUrl = loginPage + "?wa=" + action + "&wreply=" + replyUrl + "&wtrealm=" + realm;

        try {
            redirectUrl = redirectUrl + "&wctx=" + URLEncoder.encode(contextIdentifier, "UTF-8").trim();
        } catch (UnsupportedEncodingException e) {
            throw new PassiveSTSException("Error occurred while url encoding WCTX: " + contextIdentifier, e);
        }
        return redirectUrl;
    }


}
