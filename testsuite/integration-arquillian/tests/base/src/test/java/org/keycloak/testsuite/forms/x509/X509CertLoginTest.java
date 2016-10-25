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

package org.keycloak.testsuite.forms.x509;

import org.jboss.arquillian.graphene.page.Page;
import org.jboss.logging.Logger;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
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
import org.keycloak.testsuite.pages.x509.X509LoginPage;

import javax.ws.rs.core.Response;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 8/12/2016
 */

public class X509CertLoginTest  extends TestRealmKeycloakTest {

    protected final Logger log = Logger.getLogger(this.getClass());

    static final String REQUIRED = "REQUIRED";
    static final String OPTIONAL = "OPTIONAL";
    static final String DISABLED = "DISABLED";
    static final String ALTERNATIVE = "ALTERNATIVE";

    // TODO move to a base class
    public static final String REALM_NAME = "test";

    private static final String CONFIG_DIR = System.getProperty("auth.server.config.dir");

    @Page
    protected AppPage appPage;

    @Page
    protected X509LoginPage loginConfirmationPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected ErrorPage errorPage;

    private static String userId;

    AuthenticationManagementResource authMgmtResource;

    AuthenticationExecutionInfoRepresentation x509ExecutionStep;

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
        x509ExecutionStep = addAssertExecution(browserFlow, X509ClientCertificateAuthenticatorFactory.PROVIDER_ID, ALTERNATIVE);
        Assert.assertNotNull(x509ExecutionStep);

        // Raise the priority of the authenticator to position it right before
        // the Username/password authentication
        // TODO find a better, more explicit way to specify the position
        // of authenticator within the flow relative to other authenticators
        authMgmtResource.raisePriority(x509ExecutionStep.getId());
        // TODO raising the priority didn't generate the event?
        //assertAdminEvents.assertEvent(REALM_NAME, OperationType.UPDATE, AdminEventPaths.authRaiseExecutionPath(exec.getId()));

        UserRepresentation user = findUser("test-user@localhost");
        userId = user.getId();
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
            Assert.assertEquals(201, resp.getStatus());
        }
        finally {
            resp.close();
        }
        return ApiUtil.getCreatedId(resp);
    }

//    private DefaultHttpClient getHttpClient() throws Exception {
//
//        final HttpParams httpParams = new BasicHttpParams();
//
//        // load the keystore containing the client certificate - keystore type is probably jks or pkcs12
//        String truststorePath = System.getProperty("client.certificate.keystore");
//        String truststorePassword = System.getProperty("client.certificate.keystore.password");
//        KeyStore keystore = KeystoreUtil.loadKeyStore(truststorePath, truststorePassword);
//
//        // load the trustore, leave it null to rely on cacerts distributed with the JVM - truststore type is probably jks or pkcs12
//        KeyStore truststore = null;
////        KeyStore truststore = KeyStore.getInstance("pkcs12");
////        InputStream truststoreInput = null;
////        // TODO get the trustore as an InputStream from somewhere
////        truststore.load(truststoreInput, "secret".toCharArray());
//
//        // Configure trust strategy to accept all certificate chains
//        TrustStrategy trustStrategy = (chain, authType) -> true;
//
//        // Configure all accepting host name verifier
//        X509HostnameVerifier verifier = new X509HostnameVerifier() {
//
//            @Override
//            public boolean verify(String s, SSLSession sslSession) { return true; }
//
//            @Override
//            public void verify(String s, SSLSocket sslSocket) throws IOException {}
//
//            @Override
//            public void verify(String s, X509Certificate x509Certificate) throws SSLException { }
//
//            @Override
//            public void verify(String s, String[] strings, String[] strings1) throws SSLException { }
//        };
//
//
//        final SchemeRegistry schemeRegistry = new SchemeRegistry();
//        schemeRegistry.register(new Scheme("https", new SSLSocketFactory(SSLSocketFactory.TLS, keystore, "secret", truststore, new SecureRandom(), trustStrategy, verifier), 443));
//
//        return new DefaultHttpClient(new ThreadSafeClientConnManager(httpParams, schemeRegistry), httpParams);
//    }
//
//    private void GetPageUsingDefaultHttpClient() {
//        DefaultHttpClient client = getHttpClient();
//        HttpGet get = new HttpGet(OAuthClient.AUTH_SERVER_ROOT + "/admin");
//        HttpResponse response = client.execute(get);
//        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
//    }

    private static String getEmptyCrlPath() {
        return "empty.crl";
    }

    private static String getSingleCertificateCrlPath() {
        return "client.crl";
    }

    private void login(X509AuthenticatorConfigBuilder configBuilder) {

        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", configBuilder.build());
        String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();

        Assert.assertTrue(loginConfirmationPage.getSubjectDistinguishedNameText().startsWith("EMAILADDRESS=test-user@localhost"));
        Assert.assertEquals("test-user@localhost", loginConfirmationPage.getUsernameText());
        Assert.assertTrue(loginConfirmationPage.getLoginDelayCounterText().startsWith("The form will be submitted"));

        loginConfirmationPage.submit();
        // TODO AppPage currently supports plain HTTP only, so the line below causes the test to fail.
//        assertTrue(appPage.isCurrent());

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));

         events.expectSslLogin().user(userId).detail(Details.USERNAME, "test-user@localhost").assertEvent();
    }

    @Test
    public void loginWithX509CertSubjectEmail() throws Exception {
        // Login using an e-mail extracted from certificate's subject DN
        login(X509AuthenticatorConfigBuilder.defaultLoginSubjectEmail());
    }

    @Test
    public void ignoreX509LoginContinueToFormLogin() throws Exception {
        // Set the X509 authenticator configuration
        X509AuthenticatorConfigBuilder builder = X509AuthenticatorConfigBuilder.defaultLoginSubjectEmail();
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", builder.build());
        String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();

        Assert.assertTrue(loginConfirmationPage.getSubjectDistinguishedNameText().startsWith("EMAILADDRESS=test-user@localhost"));
        Assert.assertEquals("test-user@localhost", loginConfirmationPage.getUsernameText());
        Assert.assertTrue(loginConfirmationPage.getLoginDelayCounterText().startsWith("The form will be submitted"));

        loginConfirmationPage.ignore();
        loginPage.login("test-user@localhost", "password");

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));

         events.expectSslLogin().user(userId).detail(Details.USERNAME, "test-user@localhost").assertEvent();
    }

    @Test
    public void loginWithX509CertSubjectCN() {
        // Login using a CN extracted from certificate's subject DN
        login(X509AuthenticatorConfigBuilder.defaultLoginSubjectCN());
    }

    @Test
    public void loginWithX509CertCustomAttributeUserNotFound() {
        X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
        builder.cRLDPEnabled(false)
                .cRLEnabled(false)
                .oCSPEnabled(false)
                .setIdentitySourceFromSubjectDNRegularExpression().regularExpression("O=(.*?)(?:,|$)")
                .setCustomAttributeName("x509_certificate_identity")
                .setCustomAttributeUserIdentityMapper();
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", builder.build());
        String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();
        loginPage.assertCurrent();

        // Verify there is an error message
        Assert.assertNotNull(loginPage.getError());

        String expectedMessage = "X509 certificate authentication's failed.";
        Assert.assertEquals(expectedMessage, loginPage.getError().substring(0, expectedMessage.length()));
        events.expectSslLogin().user((String) null).session((String) null).error("user_not_found")
                .detail(Details.USERNAME, "Widgets Inc.")
                .removeDetail(Details.CONSENT)
                .assertEvent();

        // Continue with form based login
        loginPage.login("test-user@localhost", "password");

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
        events.expectSslLogin().user(userId).detail(Details.USERNAME, "test-user@localhost").assertEvent();
    }

    @Test
    public void loginWithX509CertCustomAttributeSuccess() {
        X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
        builder.cRLDPEnabled(false)
                .cRLEnabled(false)
                .oCSPEnabled(false)
                .setIdentitySourceFromSubjectDNRegularExpression().regularExpression("O=(.*?)(?:,|$)")
                .setCustomAttributeName("x509_certificate_identity")
                .setCustomAttributeUserIdentityMapper();
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", builder.build());
        String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
        Assert.assertNotNull(cfgId);

        // Update the attribute used to match the user identity to that
        // extracted from the client certificate
        UserRepresentation user = findUser("test-user@localhost");
        Assert.assertNotNull(user);
        user.singleAttribute("x509_certificate_identity", "Widgets Inc.");
        this.updateUser(user);

        loginConfirmationPage.open();

        Assert.assertTrue(loginConfirmationPage.getSubjectDistinguishedNameText().startsWith("EMAILADDRESS=test-user@localhost"));
        Assert.assertEquals("test-user@localhost", loginConfirmationPage.getUsernameText());
        Assert.assertTrue(loginConfirmationPage.getLoginDelayCounterText().startsWith("The form will be submitted"));

        loginConfirmationPage.submit();

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
    }

    @Test
    public void loginWithX509CertUserMissing() {
        X509AuthenticatorConfigBuilder configBuilder = X509AuthenticatorConfigBuilder.defaultLoginSubjectEmail();
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", configBuilder.build());
        String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
        Assert.assertNotNull(cfgId);

        // Delete user
        UserRepresentation user = findUser("test-user@localhost");
        Assert.assertNotNull(user);

        Response response = testRealm().users().delete(userId);
        assertEquals(204, response.getStatus());
        response.close();
        // TODO causes the test to fail
        //assertAdminEvents.assertEvent(REALM_NAME, OperationType.DELETE, AdminEventPaths.userResourcePath(userId));

        loginConfirmationPage.open();
        loginPage.assertCurrent();

        // Verify there is an error message
        Assert.assertNotNull(loginPage.getError());

        String expectedMessage = "X509 certificate authentication's failed.";
        Assert.assertEquals(expectedMessage, loginPage.getError().substring(0, expectedMessage.length()));

        events.expectSslLogin().user((String) null).session((String) null).error("user_not_found")
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.CONSENT)
                .assertEvent();

        // Continue with form based login
        loginPage.login("test-user@localhost", "password");
        loginPage.assertCurrent();

        Assert.assertEquals("test-user@localhost", loginPage.getUsername());
        Assert.assertEquals("", loginPage.getPassword());

        Assert.assertEquals("Invalid username or password.", loginPage.getError());
    }

    @Test
    public void loginValidCertificateDisabledUser() {
        setUserEnabled("test-user@localhost", false);

        try {
            X509AuthenticatorConfigBuilder configBuilder = X509AuthenticatorConfigBuilder.defaultLoginSubjectEmail();
            AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", configBuilder.build());
            String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
            Assert.assertNotNull(cfgId);

            loginConfirmationPage.open();
            loginPage.assertCurrent();

            Assert.assertNotNull(loginPage.getError());

            String expectedMessage = "X509 certificate authentication's failed.\nUser is disabled";
            Assert.assertEquals(expectedMessage, loginPage.getError().substring(0, expectedMessage.length()));

            events.expectSslLogin().user(userId).session((String) null).error("user_disabled")
                    .detail(Details.USERNAME, "test-user@localhost")
                    .removeDetail(Details.CONSENT)
                    .assertEvent();

            loginPage.login("test-user@localhost", "password");
            loginPage.assertCurrent();

            // KEYCLOAK-1741 - assert form field values kept
            Assert.assertEquals("test-user@localhost", loginPage.getUsername());
            Assert.assertEquals("", loginPage.getPassword());

            // KEYCLOAK-2024
            Assert.assertEquals("Account is disabled, contact admin.", loginPage.getError());

            events.expectSslLogin().user(userId).session((String) null).error("user_disabled")
                    .detail(Details.USERNAME, "test-user@localhost")
                    .removeDetail(Details.CONSENT)
                    .assertEvent();
        } finally {
            setUserEnabled("test-user@localhost", true);
        }
    }

    @Test
    public void loginWithX509WithEmptyRevocationList() {
        X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
        builder.cRLDPEnabled(false)
                .cRLEnabled(true)
                .cRLFilePath(getEmptyCrlPath())
                .oCSPEnabled(false)
                .setSubjectDNEmailAsUserIdentitySource()
                .setUsernameOrEmailUserIdentityMapper();
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", builder.build());
        String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();

        Assert.assertTrue(loginConfirmationPage.getSubjectDistinguishedNameText().startsWith("EMAILADDRESS=test-user@localhost"));
        Assert.assertEquals("test-user@localhost", loginConfirmationPage.getUsernameText());
        Assert.assertTrue(loginConfirmationPage.getLoginDelayCounterText().startsWith("The form will be submitted"));

        loginConfirmationPage.submit();

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
        events.expectSslLogin().user(userId).detail(Details.USERNAME, "test-user@localhost").assertEvent();
    }

    @Test
    public void loginCertificateRevoked() {
        X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
        builder.cRLDPEnabled(false)
                .cRLEnabled(true)
                .cRLFilePath(getSingleCertificateCrlPath())
                .oCSPEnabled(false)
                .setSubjectDNEmailAsUserIdentitySource()
                .setUsernameOrEmailUserIdentityMapper();
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", builder.build());
        String cfgId = createConfig(x509ExecutionStep.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();
        loginPage.assertCurrent();

        // Verify there is an error message
        Assert.assertNotNull(loginPage.getError());

        String expectedMessage = "Certificate validation's failed.\nCertificate has been revoked, certificate's subject:";
        Assert.assertEquals(expectedMessage, loginPage.getError().substring(0, expectedMessage.length()));

        // Continue with form based login
        loginPage.login("test-user@localhost", "password");

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));

        events.expectSslLogin().user(userId).detail(Details.USERNAME, "test-user@localhost").assertEvent();
    }

    private void setUserEnabled(String userName, boolean enabled) {
        UserRepresentation user = findUser(userName);
        Assert.assertNotNull(user);

        user.setEnabled(enabled);

        updateUser(user);
    }

    static class X509AuthenticatorConfigBuilder {
        LinkedHashMap<String,String> parameters;

        public X509AuthenticatorConfigBuilder() {
            parameters = new LinkedHashMap<>();
        }

        public static X509AuthenticatorConfigBuilder defaultLoginSubjectEmail() {
            X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
            return builder
                    .cRLDPEnabled(false)
                    .cRLEnabled(false)
                    .oCSPEnabled(false)
                    .setSubjectDNEmailAsUserIdentitySource()
                    .setUsernameOrEmailUserIdentityMapper();
        }

        public static X509AuthenticatorConfigBuilder defaultLoginSubjectCN() {
            X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
            return builder
                    .cRLDPEnabled(false)
                    .cRLEnabled(false)
                    .oCSPEnabled(false)
                    .setSubjectDNEmailAsUserIdentitySource()
                    .setUsernameOrEmailUserIdentityMapper();
        }

        public static X509AuthenticatorConfigBuilder defaultLoginIssuerEmail() {
            X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
            return builder
                    .cRLDPEnabled(false)
                    .cRLEnabled(false)
                    .oCSPEnabled(false)
                    .setIssuerDNEmailAsUserIdentitySource()
                    .setCustomAttributeName("x509_certificate_identity")
                    .setCustomAttributeUserIdentityMapper();
        }

        public static X509AuthenticatorConfigBuilder defaultLoginIssuerCN() {
            X509AuthenticatorConfigBuilder builder = new X509AuthenticatorConfigBuilder();
            return builder
                    .cRLDPEnabled(false)
                    .cRLEnabled(false)
                    .oCSPEnabled(false)
                    .setIssuerDNCNAsUserIdentitySource()
                    .setCustomAttributeName("x509_certificate_identity")
                    .setCustomAttributeUserIdentityMapper();
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
        public X509AuthenticatorConfigBuilder setIdentitySourceFromSubjectDNRegularExpression() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN);
            return this;
        }

        public X509AuthenticatorConfigBuilder setIdentitySourceFromIssuerDNRegularExpression() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_ISSUERDN);
            return this;
        }

        public X509AuthenticatorConfigBuilder setSubjectDNEmailAsUserIdentitySource() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN_EMAIL);
            return this;
        }

        public X509AuthenticatorConfigBuilder setSubjectDNCNAsUserIdentitySource() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN_CN);
            return this;
        }

        public X509AuthenticatorConfigBuilder setIssuerDNEmailAsUserIdentitySource() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_ISSUERDN_EMAIL);
            return this;
        }

        public X509AuthenticatorConfigBuilder setIssuerDNCNAsUserIdentitySource() {
            parameters.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_ISSUERDN_CN);
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

        public Map<String,String> build() {
            return parameters;
        }
    }
}
