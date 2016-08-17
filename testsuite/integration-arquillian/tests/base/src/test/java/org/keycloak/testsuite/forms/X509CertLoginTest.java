/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
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
 *
 */

package org.keycloak.testsuite.forms;

import org.jboss.arquillian.graphene.page.Page;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.*;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.events.Details;
import org.keycloak.events.admin.OperationType;
import org.keycloak.representations.idm.*;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.TestRealmKeycloakTest;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.util.AdminEventPaths;
import org.keycloak.testsuite.util.AssertAdminEvents;
import org.keycloak.testsuite.util.RealmBuilder;
import org.keycloak.testsuite.util.UserBuilder;

import javax.ws.rs.core.Response;
import java.net.URLDecoder;
import java.util.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 8/12/2016
 */

public class X509CertLoginTest  extends TestRealmKeycloakTest {

    static final String REQUIRED = "REQUIRED";
    static final String OPTIONAL = "OPTIONAL";
    static final String DISABLED = "DISABLED";
    static final String ALTERNATIVE = "ALTERNATIVE";

    // TODO move to a base class
    public static final String REALM_NAME = "test";

    @Page
    protected AppPage appPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected ErrorPage errorPage;

    private static String userId;

    private static String user2Id;

    AuthenticationManagementResource authMgmtResource;

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Rule
    public AssertAdminEvents assertAdminEvents = new AssertAdminEvents(this);

    @Before
    public void configureFlows() {
        authMgmtResource = adminClient.realms().realm(REALM_NAME).flows();

        AuthenticationFlowRepresentation browserFlow = copyBrowserFlow();
        Assert.assertNotNull(browserFlow);

        AuthenticationFlowRepresentation directGrantFlow = copyDirectGrantFlow();
        Assert.assertNotNull(directGrantFlow);

        setBrowserFlow(browserFlow);
        Assert.assertEquals(testRealm().toRepresentation().getBrowserFlow(), browserFlow.getAlias());

        setDirectGrantFlow(directGrantFlow);
        Assert.assertEquals(testRealm().toRepresentation().getDirectGrantFlow(), directGrantFlow.getAlias());

        // Add X509 authenticator to the browser flow
        AuthenticationExecutionInfoRepresentation exec = addAssertExecution(browserFlow, X509ClientCertificateAuthenticatorFactory.PROVIDER_ID, ALTERNATIVE);
        Assert.assertNotNull(exec);

        // Raise the priority of the authenticator to position it right before
        // the Username/password authentication
        // TODO find a better, more explicit way to specify the position
        // of authenticator within the flow relative to other authenticators
        authMgmtResource.raisePriority(exec.getId());

        // Set the X509 authenticator configuration
        X509AuthenticatorConfigBuilder builder = X509AuthenticatorConfigBuilder.defaults();
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", builder.build());
        String cfgId = createConfig(exec.getId(), cfg);
        Assert.assertNotNull(cfgId);
        // TODO the following statement asserts, the actual value is null?
        //assertAdminEvents.assertEvent(REALM_NAME, OperationType.CREATE, AdminEventPaths.authAddExecutionConfigPath(exec.getId()), cfg);
    }

    private AuthenticationExecutionInfoRepresentation addAssertExecution(AuthenticationFlowRepresentation flow, String providerId, String requirement) {
        AuthenticationExecutionRepresentation rep = new AuthenticationExecutionRepresentation();
        rep.setPriority(10);
        rep.setAuthenticator(providerId);
        rep.setRequirement(requirement);
        rep.setParentFlow(flow.getId());

        Response response = authMgmtResource.addExecution(rep);
        // TODO the following statement asserts, the actual value is null?
        //assertAdminEvents.assertEvent(REALM_NAME, OperationType.CREATE, AssertAdminEvents.isExpectedPrefixFollowedByUuid(AdminEventPaths.authMgmtBasePath() + "/executions"), rep);
        try {
            Assert.assertEquals("added execution", 201, response.getStatus());
        } finally {
            response.close();
        }
        List<AuthenticationExecutionInfoRepresentation> executionReps = authMgmtResource.getExecutions(flow.getAlias());
        return findExecution(providerId, executionReps);
    }

    AuthenticationExecutionInfoRepresentation findExecution(String providerId, List<AuthenticationExecutionInfoRepresentation> reps) {
        for (AuthenticationExecutionInfoRepresentation exec : reps) {
            if (providerId.equals(exec.getProviderId())) {
                return exec;
            }
        }
        return null;
    }

    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
        UserRepresentation user = UserBuilder.create()
                .id("login-test")
                .username("login-test")
                .email("login@test.com")
                .enabled(true)
                .password("password")
                .build();
        userId = user.getId();

        UserRepresentation user2 = UserBuilder.create()
                .id("login-test2")
                .username("login-test2")
                .email("login2@test.com")
                .enabled(true)
                .password("password")
                .build();
        user2Id = user2.getId();

        RealmBuilder.edit(testRealm)
                .user(user)
                .user(user2);
    }

    AuthenticationFlowRepresentation copyFlow(String existingFlow, String newFlow) {
        // copy that should succeed
        HashMap<String, String> params = new HashMap<>();
        params.put("newName", newFlow);
        Response response = authMgmtResource.copy(existingFlow, params);
        assertAdminEvents.assertEvent(REALM_NAME, OperationType.CREATE, URLDecoder.decode(AdminEventPaths.authCopyFlowPath(existingFlow)), params);
        try {
            Assert.assertEquals("Copy flow", 201, response.getStatus());
        } finally {
            response.close();
        }
        for (AuthenticationFlowRepresentation flow : authMgmtResource.getFlows()) {
            if (flow.getAlias().equalsIgnoreCase(newFlow)) {
                return flow;
            }
        }
        return null;
    }

    AuthenticationFlowRepresentation copyBrowserFlow() {

        RealmRepresentation realm = testRealm().toRepresentation();
        return copyFlow(realm.getBrowserFlow(), "Copy-of-browser");
    }

    void setBrowserFlow(AuthenticationFlowRepresentation flow) {
        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setBrowserFlow(flow.getAlias());
        testRealm().update(realm);
    }

    AuthenticationFlowRepresentation copyDirectGrantFlow() {
        RealmRepresentation realm = testRealm().toRepresentation();
        return copyFlow(realm.getDirectGrantFlow(), "Copy-of-direct-grant");
    }

    void setDirectGrantFlow(AuthenticationFlowRepresentation flow) {
        RealmRepresentation realm = testRealm().toRepresentation();
        realm.setDirectGrantFlow(flow.getAlias());
        testRealm().update(realm);
    }

    static AuthenticatorConfigRepresentation newConfig(String alias, Map<String,String> params) {
        AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
        config.setAlias(alias);
        config.setConfig(params);
        return config;
    }

    private String createConfig(String executionId, AuthenticatorConfigRepresentation cfg) {
        Response resp = authMgmtResource.newExecutionConfig(executionId, cfg);
        try {
            org.keycloak.testsuite.Assert.assertEquals(201, resp.getStatus());
        }
        finally {
            resp.close();
        }
        return ApiUtil.getCreatedId(resp);
    }

    @Test
    public void loginNoCertificate() {

//        loginPage.open();
//        loginPage.open();
//        loginPage.login("login-test", "invalid");
//
//        loginPage.assertCurrent();
//
//        // KEYCLOAK-1741 - assert form field values kept
//        Assert.assertEquals("login-test", loginPage.getUsername());
//        Assert.assertEquals("", loginPage.getPassword());
//
//        Assert.assertEquals("Invalid username or password.", loginPage.getError());
//
//        events.expectLogin().user(userId).session((String) null).error("invalid_user_credentials")
//                .detail(Details.USERNAME, "login-test")
//                .removeDetail(Details.CONSENT)
//                .assertEvent();
    }

    @Test
    public void loginUntrustedCertificate() {
//        loginPage.open();
//        loginPage.missingPassword("login-test");
//
//        loginPage.assertCurrent();
//
//        // KEYCLOAK-1741 - assert form field values kept
//        Assert.assertEquals("login-test", loginPage.getUsername());
//        Assert.assertEquals("", loginPage.getPassword());
//
//        Assert.assertEquals("Invalid username or password.", loginPage.getError());
//
//        events.expectLogin().user(userId).session((String) null).error("invalid_user_credentials")
//                .detail(Details.USERNAME, "login-test")
//                .removeDetail(Details.CONSENT)
//                .assertEvent();
    }

    @Test
    public void loginTrustedCertificateInvalidUser() {
//        loginPage.open();
//        loginPage.login("invalid", "password");
//
//        loginPage.assertCurrent();
//
//        // KEYCLOAK-1741 - assert form field values kept
//        Assert.assertEquals("invalid", loginPage.getUsername());
//        Assert.assertEquals("", loginPage.getPassword());
//
//        Assert.assertEquals("Invalid username or password.", loginPage.getError());
//
//        events.expectLogin().user((String) null).session((String) null).error("user_not_found")
//                .detail(Details.USERNAME, "invalid")
//                .removeDetail(Details.CONSENT)
//                .assertEvent();
//
//        loginPage.login("login-test", "password");
//
//        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
//        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
//
//        events.expectLogin().user(userId).detail(Details.USERNAME, "login-test").assertEvent();
    }

    @Test
    public void loginValidCertificateDisabledUser() {
//        setUserEnabled("login-test", false);
//
//        try {
//            loginPage.open();
//            loginPage.login("login-test", "password");
//
//            loginPage.assertCurrent();
//
//            // KEYCLOAK-1741 - assert form field values kept
//            Assert.assertEquals("login-test", loginPage.getUsername());
//            Assert.assertEquals("", loginPage.getPassword());
//
//            // KEYCLOAK-2024
//            Assert.assertEquals("Account is disabled, contact admin.", loginPage.getError());
//
//            events.expectLogin().user(userId).session((String) null).error("user_disabled")
//                    .detail(Details.USERNAME, "login-test")
//                    .removeDetail(Details.CONSENT)
//                    .assertEvent();
//        } finally {
//            setUserEnabled("login-test", true);
//        }
    }

    static class X509AuthenticatorConfigBuilder {
        LinkedHashMap<String,String> parameters;

        public X509AuthenticatorConfigBuilder() {
            parameters = new LinkedHashMap<>();
        }

        public static X509AuthenticatorConfigBuilder defaults() {
            X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
            return builder
                    .cRLDPEnabled(false)
                    .cRLEnabled(false)
                    .oCSPEnabled(false)
                    .regularExpression("emailAddress=(.*?)(?:,|$)")
                    .setSubjectDNAsUserIdentitySource()
                    .setTrustStorePassword("changeit")
                    .setUsernameOrEmailUserIdentityMapper();
        }

        public X509AuthenticatorConfigBuilder regularExpression(String pattern) {
            parameters.put(REGULAR_EXPRESSION, pattern);
            return this;
        }
        public X509AuthenticatorConfigBuilder cRLEnabled(boolean enabled) {
            parameters.put(ENABLE_CRL, enabled ? "true" : "false");
            return this;
        }
        public X509AuthenticatorConfigBuilder oCSPEnabled(boolean enabled) {
            parameters.put(ENABLE_OCSP, enabled ? "true" : "false");
            return this;
        }
        public X509AuthenticatorConfigBuilder cRLDPEnabled(boolean enabled) {
            parameters.put(ENABLE_CRLDP, enabled ? "true" : "false");
            return this;
        }
        public X509AuthenticatorConfigBuilder cRLFilePath(String filePath) {
            parameters.put(CRL_RELATIVE_PATH, filePath);
            return this;
        }
        public X509AuthenticatorConfigBuilder oCSPResponderURI(String responderURI) {
            parameters.put(OCSPRESPONDER_URI, responderURI);
            return this;
        }
        public X509AuthenticatorConfigBuilder setSubjectDNAsUserIdentitySource() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN);
            return this;
        }
        public X509AuthenticatorConfigBuilder setIssuerDNAsUserIdentitySource() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_ISSUERDN);
            return this;
        }
        public X509AuthenticatorConfigBuilder setSerialNumberAsUserIdentitySource() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SERIALNUMBER);
            return this;
        }
        public X509AuthenticatorConfigBuilder setUsernameOrEmailUserIdentityMapper() {
            parameters.put(USER_MAPPER_SELECTION, USERNAME_EMAIL_MAPPER);
            return this;
        }
        public X509AuthenticatorConfigBuilder setCustomAttributeUserIdentityMapper() {
            parameters.put(USER_MAPPER_SELECTION, USER_ATTRIBUTE_MAPPER);
            return this;
        }
        public X509AuthenticatorConfigBuilder setCustomAttributeName(String userAttribute) {
            parameters.put(CUSTOM_ATTRIBUTE_NAME, userAttribute);
            return this;
        }
        public X509AuthenticatorConfigBuilder setKeyUsage(String keyUsage) {
            parameters.put(CERTIFICATE_KEY_USAGE, keyUsage);
            return this;
        }
        public X509AuthenticatorConfigBuilder setExtendedKeyUsage(String extendedKeyUsage) {
            parameters.put(CERTIFICATE_EXTENDED_KEY_USAGE, extendedKeyUsage);
            return this;
        }
        public X509AuthenticatorConfigBuilder setTrustStorePath(String trustStorePath) {
            parameters.put(TRUSTSTORE_PATH, trustStorePath);
            return this;
        }
        public X509AuthenticatorConfigBuilder setTrustStorePassword(String password) {
            parameters.put(TRUSTSTORE_PASSWORD, password);
            return this;
        }
        public X509AuthenticatorConfigBuilder setTrustStoreType(String type) {
            parameters.put(TRUSTSTORE_TYPE, type);
            return this;
        }

        public Map<String,String> build() {
            return parameters;
        }
    }
}
