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
import org.junit.*;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsernameFactory;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticatorFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.representations.idm.*;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.TestRealmKeycloakTest;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.util.*;
import org.keycloak.testsuite.pages.x509.X509IdentityConfirmationPage;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.net.URLDecoder;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel.IdentityMapperType.USERNAME_EMAIL;
import static org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel.IdentityMapperType.USER_ATTRIBUTE;
import static org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel.MappingSourceType.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 8/12/2016
 */

public class X509CertLoginTest  extends TestRealmKeycloakTest {

    public static final String EMPTY_CRL_PATH = "empty.crl";
    public static final String CLIENT_CRL_PATH = "client.crl";
    protected final Logger log = Logger.getLogger(this.getClass());

    static final String REQUIRED = "REQUIRED";
    static final String OPTIONAL = "OPTIONAL";
    static final String DISABLED = "DISABLED";
    static final String ALTERNATIVE = "ALTERNATIVE";

    // TODO move to a base class
    public static final String REALM_NAME = "test";

    @Page
    protected AppPage appPage;

    @Page
    protected X509IdentityConfirmationPage loginConfirmationPage;

    @Page
    protected LoginPage loginPage;

    @Page
    protected ErrorPage errorPage;

    private static String userId;

    private static String userId2;

    AuthenticationManagementResource authMgmtResource;

    AuthenticationExecutionInfoRepresentation browserExecution;

    AuthenticationExecutionInfoRepresentation directGrantExecution;
    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Rule
    public AssertAdminEvents assertAdminEvents = new AssertAdminEvents(this);

    @Before
    public void configureFlows() {
        authMgmtResource = adminClient.realms().realm(REALM_NAME).flows();

        AuthenticationFlowRepresentation browserFlow = copyBrowserFlow();
        Assert.assertNotNull(browserFlow);

        AuthenticationFlowRepresentation directGrantFlow = createDirectGrantFlow();
        Assert.assertNotNull(directGrantFlow);

        setBrowserFlow(browserFlow);
        Assert.assertEquals(testRealm().toRepresentation().getBrowserFlow(), browserFlow.getAlias());

        setDirectGrantFlow(directGrantFlow);
        Assert.assertEquals(testRealm().toRepresentation().getDirectGrantFlow(), directGrantFlow.getAlias());
        Assert.assertEquals(0, directGrantFlow.getAuthenticationExecutions().size());

        // Add X509 cert authenticator to the direct grant flow
        directGrantExecution = addAssertExecution(directGrantFlow, ValidateX509CertificateUsernameFactory.PROVIDER_ID, REQUIRED);
        Assert.assertNotNull(directGrantExecution);

        directGrantFlow = authMgmtResource.getFlow(directGrantFlow.getId());
        Assert.assertNotNull(directGrantFlow.getAuthenticationExecutions());
        Assert.assertEquals(1, directGrantFlow.getAuthenticationExecutions().size());

        // Add X509 authenticator to the browser flow
        browserExecution = addAssertExecution(browserFlow, X509ClientCertificateAuthenticatorFactory.PROVIDER_ID, ALTERNATIVE);
        Assert.assertNotNull(browserExecution);

        // Raise the priority of the authenticator to position it right before
        // the Username/password authentication
        // TODO find a better, more explicit way to specify the position
        // of authenticator within the flow relative to other authenticators
        authMgmtResource.raisePriority(browserExecution.getId());
        // TODO raising the priority didn't generate the event?
        //assertAdminEvents.assertEvent(REALM_NAME, OperationType.UPDATE, AdminEventPaths.authRaiseExecutionPath(exec.getId()));

        UserRepresentation user = findUser("test-user@localhost");
        userId = user.getId();

        user.singleAttribute("x509_certificate_identity","-");
        updateUser(user);
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

        ClientRepresentation app = ClientBuilder.create()
                .id(KeycloakModelUtils.generateId())
                .clientId("resource-owner")
                .directAccessGrants()
                .secret("secret")
                .build();

        UserRepresentation user = UserBuilder.create()
                .id("localhost")
                .username("localhost")
                .email("localhost@localhost")
                .enabled(true)
                .password("password")
                .build();

        userId2 = user.getId();

        ClientRepresentation client = findTestApp(testRealm);
        URI baseUri = URI.create(client.getRedirectUris().get(0));
        URI redir = URI.create("https://localhost:" + System.getProperty("app.server.https.port", "8543") + baseUri.getRawPath());
        client.getRedirectUris().add(redir.toString());

        testRealm.setBruteForceProtected(true);
        testRealm.setFailureFactor(2);

        RealmBuilder.edit(testRealm)
                .user(user)
                .client(app);
    }

    AuthenticationFlowRepresentation createFlow(AuthenticationFlowRepresentation flowRep) {
        Response response = authMgmtResource.createFlow(flowRep);
        try {
            org.keycloak.testsuite.Assert.assertEquals(201, response.getStatus());
        }
        finally {
            response.close();
        }
        assertAdminEvents.assertEvent(REALM_NAME, OperationType.CREATE, AssertAdminEvents.isExpectedPrefixFollowedByUuid(AdminEventPaths.authFlowsPath()), flowRep);

        for (AuthenticationFlowRepresentation flow : authMgmtResource.getFlows()) {
            if (flow.getAlias().equalsIgnoreCase(flowRep.getAlias())) {
                return flow;
            }
        }
        return null;
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

    AuthenticationFlowRepresentation createDirectGrantFlow() {
        AuthenticationFlowRepresentation newFlow = newFlow("Copy-of-direct-grant", "desc", AuthenticationFlow.BASIC_FLOW, true, false);
        return createFlow(newFlow);
    }

    AuthenticationFlowRepresentation newFlow(String alias, String description,
                                             String providerId, boolean topLevel, boolean builtIn) {
        AuthenticationFlowRepresentation flow = new AuthenticationFlowRepresentation();
        flow.setAlias(alias);
        flow.setDescription(description);
        flow.setProviderId(providerId);
        flow.setTopLevel(topLevel);
        flow.setBuiltIn(builtIn);
        return flow;
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

    private void login(X509AuthenticatorConfigModel config, String userId, String username, String attemptedUsername) {

        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", config.getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();

        Assert.assertTrue(loginConfirmationPage.getSubjectDistinguishedNameText().startsWith("EMAILADDRESS=test-user@localhost"));
        Assert.assertEquals(username, loginConfirmationPage.getUsernameText());
        Assert.assertTrue(loginConfirmationPage.getLoginDelayCounterText().startsWith("The form will be submitted"));

        loginConfirmationPage.confirm();

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));

         events.expectLogin()
                 .user(userId)
                 .detail(Details.USERNAME, attemptedUsername)
                 .removeDetail(Details.REDIRECT_URI)
                 .assertEvent();
    }

    @Test
    public void loginAsUserFromCertSubjectEmail() throws Exception {
        // Login using an e-mail extracted from certificate's subject DN
        login(createLoginSubjectEmail2UsernameOrEmailConfig(), userId, "test-user@localhost", "test-user@localhost");
    }

    @Test
    public void loginIgnoreX509IdentityContinueToFormLogin() throws Exception {
        // Set the X509 authenticator configuration
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", createLoginSubjectEmail2UsernameOrEmailConfig().getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();

        Assert.assertTrue(loginConfirmationPage.getSubjectDistinguishedNameText().startsWith("EMAILADDRESS=test-user@localhost"));
        Assert.assertEquals("test-user@localhost", loginConfirmationPage.getUsernameText());
        Assert.assertTrue(loginConfirmationPage.getLoginDelayCounterText().startsWith("The form will be submitted"));

        loginConfirmationPage.ignore();
        loginPage.login("test-user@localhost", "password");

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));

         events.expectLogin()
                 .user(userId)
                 .detail(Details.USERNAME, "test-user@localhost")
                 .removeDetail(Details.REDIRECT_URI)
                 .assertEvent();
    }

    @Test
    public void loginAsUserFromCertSubjectCN() {
        // Login using a CN extracted from certificate's subject DN
        login(createLoginSubjectCN2UsernameOrEmailConfig(), userId, "test-user@localhost", "test-user@localhost");
    }

    @Test
    public void loginAsUserFromCertIssuerCN() {
        login(createLoginIssuerCNToUsernameOrEmailConfig(), userId2, "localhost", "localhost");
    }

    @Test
    public void loginAsUserFromCertIssuerCNMappedToUserAttribute() {

        UserRepresentation user = testRealm().users().get(userId2).toRepresentation();
        Assert.assertNotNull(user);

        user.singleAttribute("x509_certificate_identity", "Keycloak");
        this.updateUser(user);

        login(createLoginIssuerDN_OU2CustomAttributeConfig(), userId2, "localhost", "Keycloak");
    }

    @Test
    public void loginDuplicateUsersNotAllowed() {

        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", createLoginIssuerDN_OU2CustomAttributeConfig().getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        // Set up the users so that the identity extracted from X509 client cert
        // matches more than a single user to trigger DuplicateModelException.

        UserRepresentation user = testRealm().users().get(userId2).toRepresentation();
        Assert.assertNotNull(user);

        user.singleAttribute("x509_certificate_identity", "Keycloak");
        this.updateUser(user);

        user = testRealm().users().get(userId).toRepresentation();
        Assert.assertNotNull(user);

        user.singleAttribute("x509_certificate_identity", "Keycloak");
        this.updateUser(user);

        loginPage.open();

        String expectedMessage = "X509 certificate authentication's failed.";
        Assert.assertEquals(expectedMessage, loginPage.getError().substring(0, expectedMessage.length()));

        loginPage.login("test-user@localhost", "password");

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));

        events.expectLogin()
                .user(userId)
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();
    }

    @Test
    public void loginAttemptedNoConfig() {

        loginConfirmationPage.open();
        loginPage.assertCurrent();

        String expectedMessage = "X509 client authentication has not been configured yet";
        Assert.assertEquals(expectedMessage, loginPage.getInfoMessage().substring(0, expectedMessage.length()));
        // Continue with form based login
        loginPage.login("test-user@localhost", "password");

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
        events.expectLogin()
                .user(userId)
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();
    }

    @Test
    public void loginWithX509CertCustomAttributeUserNotFound() {
        X509AuthenticatorConfigModel config =
                new X509AuthenticatorConfigModel()
                        .setConfirmationPageAllowed(true)
                        .setMappingSourceType(SUBJECTDN)
                        .setRegularExpression("O=(.*?)(?:,|$)")
                        .setCustomAttributeName("x509_certificate_identity")
                        .setUserIdentityMapperType(USER_ATTRIBUTE);
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", config.getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        loginConfirmationPage.open();
        loginPage.assertCurrent();

        // Verify there is an error message
        Assert.assertNotNull(loginPage.getError());

        String expectedMessage = "X509 certificate authentication's failed.";
        Assert.assertEquals(expectedMessage, loginPage.getError().substring(0, expectedMessage.length()));
        events.expectLogin()
                .user((String) null)
                .session((String) null)
                .error("user_not_found")
                .detail(Details.USERNAME, "Widgets Inc.")
                .removeDetail(Details.CONSENT)
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();

        // Continue with form based login
        loginPage.login("test-user@localhost", "password");

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
        events.expectLogin()
                .user(userId)
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();
    }

    @Test
    public void loginWithX509CertCustomAttributeSuccess() {
        X509AuthenticatorConfigModel config =
                new X509AuthenticatorConfigModel()
                        .setConfirmationPageAllowed(true)
                        .setMappingSourceType(SUBJECTDN)
                        .setRegularExpression("O=(.*?)(?:,|$)")
                        .setCustomAttributeName("x509_certificate_identity")
                        .setUserIdentityMapperType(USER_ATTRIBUTE);
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", config.getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
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

        loginConfirmationPage.confirm();

        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
    }

    @Test
    public void loginWithX509CertBadUserOrNotFound() {
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", createLoginSubjectEmail2UsernameOrEmailConfig().getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
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

        events.expectLogin()
                .user((String) null)
                .session((String) null)
                .error("user_not_found")
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.CONSENT)
                .removeDetail(Details.REDIRECT_URI)
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
            AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", createLoginSubjectEmail2UsernameOrEmailConfig().getConfig());
            String cfgId = createConfig(browserExecution.getId(), cfg);
            Assert.assertNotNull(cfgId);

            loginConfirmationPage.open();
            loginPage.assertCurrent();

            Assert.assertNotNull(loginPage.getError());

            String expectedMessage = "X509 certificate authentication's failed.\nUser is disabled";
            Assert.assertEquals(expectedMessage, loginPage.getError().substring(0, expectedMessage.length()));

            events.expectLogin()
                    .user(userId)
                    .session((String) null)
                    .error("user_disabled")
                    .detail(Details.USERNAME, "test-user@localhost")
                    .removeDetail(Details.CONSENT)
                    .removeDetail(Details.REDIRECT_URI)
                    .assertEvent();

            loginPage.login("test-user@localhost", "password");
            loginPage.assertCurrent();

            // KEYCLOAK-1741 - assert form field values kept
            Assert.assertEquals("test-user@localhost", loginPage.getUsername());
            Assert.assertEquals("", loginPage.getPassword());

            // KEYCLOAK-2024
            Assert.assertEquals("Account is disabled, contact admin.", loginPage.getError());

            events.expectLogin()
                    .user(userId)
                    .session((String) null)
                    .error("user_disabled")
                    .detail(Details.USERNAME, "test-user@localhost")
                    .removeDetail(Details.CONSENT)
                    .removeDetail(Details.REDIRECT_URI)
                    .assertEvent();
        } finally {
            setUserEnabled("test-user@localhost", true);
        }
    }

    @Test
    public void loginWithX509WithEmptyRevocationList() {
        X509AuthenticatorConfigModel config =
                new X509AuthenticatorConfigModel()
                        .setCRLEnabled(true)
                        .setCRLRelativePath(EMPTY_CRL_PATH)
                        .setConfirmationPageAllowed(true)
                        .setMappingSourceType(SUBJECTDN_EMAIL)
                        .setUserIdentityMapperType(USERNAME_EMAIL);
        login(config, userId, "test-user@localhost", "test-user@localhost");
    }

    @Test
    public void loginCertificateRevoked() {
        X509AuthenticatorConfigModel config =
                new X509AuthenticatorConfigModel()
                        .setCRLEnabled(true)
                        .setCRLRelativePath(CLIENT_CRL_PATH)
                        .setConfirmationPageAllowed(true)
                        .setMappingSourceType(SUBJECTDN_EMAIL)
                        .setUserIdentityMapperType(USERNAME_EMAIL);
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", config.getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
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

        events.expectLogin()
                .user(userId)
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();
    }

    @Test
    public void loginNoIdentityConfirmationPage() {
        X509AuthenticatorConfigModel config =
                new X509AuthenticatorConfigModel()
                    .setConfirmationPageAllowed(false)
                    .setMappingSourceType(SUBJECTDN_EMAIL)
                    .setUserIdentityMapperType(USERNAME_EMAIL);
        AuthenticatorConfigRepresentation cfg = newConfig("x509-browser-config", config.getConfig());
        String cfgId = createConfig(browserExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        oauth.openLoginForm();
        // X509 authenticator extracts the user identity, maps it to an existing
        // user and automatically logs the user in without prompting to confirm
        // the identity.
        Assert.assertEquals(AppPage.RequestType.AUTH_RESPONSE, appPage.getRequestType());
        Assert.assertNotNull(oauth.getCurrentQuery().get(OAuth2Constants.CODE));
        events.expectLogin()
                .user(userId)
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();
    }

    @Test
    public void loginResourceOwnerPasswordFailedOnDuplicateUsers() throws Exception {

        AuthenticatorConfigRepresentation cfg = newConfig("x509-directgrant-config", createLoginIssuerDN_OU2CustomAttributeConfig().getConfig());
        String cfgId = createConfig(directGrantExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        // Set up the users so that the identity extracted from X509 client cert
        // matches more than a single user to trigger DuplicateModelException.

        UserRepresentation user = testRealm().users().get(userId2).toRepresentation();
        Assert.assertNotNull(user);

        user.singleAttribute("x509_certificate_identity", "Keycloak");
        this.updateUser(user);

        user = testRealm().users().get(userId).toRepresentation();
        Assert.assertNotNull(user);

        user.singleAttribute("x509_certificate_identity", "Keycloak");
        this.updateUser(user);

        oauth.clientId("resource-owner");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "", "", null);

        assertEquals(401, response.getStatusCode());
        assertEquals("invalid_request", response.getError());

        String errorDesc = "X509 certificate authentication's failed.";
        assertEquals(errorDesc, response.getErrorDescription().substring(0, errorDesc.length()));
    }

    @Test
    public void loginResourceOwnerPasswordFailedOnInvalidUser() throws Exception {

        AuthenticatorConfigRepresentation cfg = newConfig("x509-directgrant-config", createLoginIssuerDN_OU2CustomAttributeConfig().getConfig());
        String cfgId = createConfig(directGrantExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        UserRepresentation user = testRealm().users().get(userId2).toRepresentation();
        Assert.assertNotNull(user);

        user.singleAttribute("x509_certificate_identity", "-");
        this.updateUser(user);

        oauth.clientId("resource-owner");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "", "", null);

        events.expectLogin()
                .user((String) null)
                .session((String) null)
                .error(Errors.INVALID_USER_CREDENTIALS)
                .client("resource-owner")
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.USERNAME)
                .removeDetail(Details.CONSENT)
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();

        assertEquals(401, response.getStatusCode());
        assertEquals("invalid_grant", response.getError());
        assertEquals("Invalid user credentials", response.getErrorDescription());
    }

    @Test
    public void loginResourceOwnerPasswordFailedDisabledUser() throws Exception {
        setUserEnabled("test-user@localhost", false);

        try {
            AuthenticatorConfigRepresentation cfg = newConfig("x509-directgrant-config", createLoginSubjectEmail2UsernameOrEmailConfig().getConfig());
            String cfgId = createConfig(directGrantExecution.getId(), cfg);
            Assert.assertNotNull(cfgId);

            oauth.clientId("resource-owner");
            OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "", "", null);

            events.expectLogin()
                    .user(userId)
                    .session((String) null)
                    .error(Errors.USER_DISABLED)
                    .client("resource-owner")
                    .detail(Details.USERNAME, "test-user@localhost")
                    .removeDetail(Details.CODE_ID)
                    .removeDetail(Details.CONSENT)
                    .removeDetail(Details.REDIRECT_URI)
                    .assertEvent();

            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
            assertEquals("invalid_grant", response.getError());
            assertEquals("Account disabled", response.getErrorDescription());

        } finally {
            setUserEnabled("test-user@localhost", true);
        }
    }

    private void loginResourceOwnerCredentialsForceTemporaryAccountLock() throws Exception {
        X509AuthenticatorConfigModel config = new X509AuthenticatorConfigModel()
                .setMappingSourceType(ISSUERDN)
                .setRegularExpression("OU=(.*?)(?:,|$)")
                .setUserIdentityMapperType(USER_ATTRIBUTE)
                .setCustomAttributeName("x509_certificate_identity");

        AuthenticatorConfigRepresentation cfg = newConfig("x509-directgrant-config", config.getConfig());
        String cfgId = createConfig(directGrantExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        UserRepresentation user = testRealm().users().get(userId).toRepresentation();
        Assert.assertNotNull(user);

        user.singleAttribute("x509_certificate_identity", "-");
        this.updateUser(user);

        oauth.clientId("resource-owner");
        OAuthClient.AccessTokenResponse response;
        response = oauth.doGrantAccessTokenRequest("secret", "", "", null);
        response = oauth.doGrantAccessTokenRequest("secret", "", "", null);
        response = oauth.doGrantAccessTokenRequest("secret", "", "", null);

        events.clear();
    }


    @Test
    @Ignore
    public void loginResourceOwnerPasswordFailedTemporarilyDisabledUser() throws Exception {

        loginResourceOwnerCredentialsForceTemporaryAccountLock();

        AuthenticatorConfigRepresentation cfg = newConfig("x509-directgrant-config", createLoginSubjectEmail2UsernameOrEmailConfig().getConfig());
        String cfgId = createConfig(directGrantExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        oauth.clientId("resource-owner");
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest("secret", "", "", null);

        events.expectLogin()
                .user(userId)
                .session((String) null)
                .error(Errors.USER_TEMPORARILY_DISABLED)
                .detail(Details.USERNAME, "test-user@localhost")
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.CONSENT)
                .removeDetail(Details.REDIRECT_URI)
                .assertEvent();

        assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatusCode());
        assertEquals("invalid_grant", response.getError());
        assertEquals("Account temporarily disabled", response.getErrorDescription());
    }


    private void doResourceOwnerPasswordLogin(String clientId, String clientSecret, String login, String password) throws Exception {

        oauth.clientId(clientId);
        OAuthClient.AccessTokenResponse response = oauth.doGrantAccessTokenRequest(clientSecret, "", "", null);

        assertEquals(200, response.getStatusCode());

        AccessToken accessToken = oauth.verifyToken(response.getAccessToken());
        RefreshToken refreshToken = oauth.verifyRefreshToken(response.getRefreshToken());

        events.expectLogin()
                .client(clientId)
                .user(userId)
                .session(accessToken.getSessionState())
                .detail(Details.GRANT_TYPE, OAuth2Constants.PASSWORD)
                .detail(Details.TOKEN_ID, accessToken.getId())
                .detail(Details.REFRESH_TOKEN_ID, refreshToken.getId())
                .detail(Details.USERNAME, login)
                .removeDetail(Details.CODE_ID)
                .removeDetail(Details.REDIRECT_URI)
                .removeDetail(Details.CONSENT)
                .assertEvent();
    }

    @Test
    public void loginResourceOwnerPassword() throws Exception {
        X509AuthenticatorConfigModel config =
                new X509AuthenticatorConfigModel()
                        .setMappingSourceType(SUBJECTDN_EMAIL)
                        .setUserIdentityMapperType(USERNAME_EMAIL);
        AuthenticatorConfigRepresentation cfg = newConfig("x509-directgrant-config", config.getConfig());
        String cfgId = createConfig(directGrantExecution.getId(), cfg);
        Assert.assertNotNull(cfgId);

        doResourceOwnerPasswordLogin("resource-owner", "secret", "test-user@localhost", "");
    }

    private void setUserEnabled(String userName, boolean enabled) {
        UserRepresentation user = findUser(userName);
        Assert.assertNotNull(user);

        user.setEnabled(enabled);

        updateUser(user);
    }

    private X509AuthenticatorConfigModel createLoginSubjectEmail2UsernameOrEmailConfig() {
        return new X509AuthenticatorConfigModel()
                .setConfirmationPageAllowed(true)
                .setMappingSourceType(SUBJECTDN_EMAIL)
                .setUserIdentityMapperType(USERNAME_EMAIL);
    }

    private X509AuthenticatorConfigModel createLoginSubjectCN2UsernameOrEmailConfig() {
        return new X509AuthenticatorConfigModel()
                .setConfirmationPageAllowed(true)
                .setMappingSourceType(SUBJECTDN_CN)
                .setUserIdentityMapperType(USERNAME_EMAIL);
    }

    private X509AuthenticatorConfigModel createLoginIssuerCNToUsernameOrEmailConfig() {
        return new X509AuthenticatorConfigModel()
                .setConfirmationPageAllowed(true)
                .setMappingSourceType(ISSUERDN_CN)
                .setUserIdentityMapperType(USERNAME_EMAIL);
    }

    private X509AuthenticatorConfigModel createLoginIssuerDN_OU2CustomAttributeConfig() {
        return new X509AuthenticatorConfigModel()
                .setConfirmationPageAllowed(true)
                .setMappingSourceType(ISSUERDN)
                .setRegularExpression("OU=(.*?)(?:,|$)")
                .setUserIdentityMapperType(USER_ATTRIBUTE)
                .setCustomAttributeName("x509_certificate_identity");
    }
}
