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

package org.keycloak.test.authentication.authenticators.x509;

import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.UserIdentityToModelMapper;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsername;
import org.keycloak.common.util.CertificateBuilder;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.*;

import javax.ws.rs.core.Response;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 10/21/2016
 */

public class UserIdentityTest {

    public static final String CERTIFICATE_SUBJECTDN = "username,OU=dev,E=username@example.com";
    public static final String ROOT_SUBJECTDN = "IDP,E=issuer@example.org";
    private Response nullCertificateResponse;
    private Response configurationIsMissingResponse;
    private Response invalidDatesResponse;
    private Response nullUserIdentityResponse;
    private Response invalidUserResponse;
    private Response invalidUserCredentialsResponse;
    private Response accountDisabledResponse;
    private Response accountTemporarilyDisabledResponse;
    @Spy private ValidateX509CertificateUsername authenticator;
    @Mock private EventBuilder events;
    @Mock private UserModel user;
    @Mock private ClientSessionModel clientSession;
    @Mock private HttpRequest context;
    @Mock private AuthenticationFlowContext flowContext;
    @Mock private AuthenticatorConfigModel config;
    @Mock private UserIdentityToModelMapper userIdModelMapper;
    @Mock private RealmModel realm;
    @Mock private BruteForceProtector bruteForceProtector;
    @Spy private CertificateValidator.CertificateValidatorBuilder validatorBuilder;
    @Spy private CertificateValidator mockValidator;

    private static X509Certificate[] clientCertificates;
    private static X509Certificate rootCertificate;

    @BeforeClass
    public static void setupCerts() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpPair = generator.generateKeyPair();
        KeyPair clientPair = generator.generateKeyPair();

        X509Certificate rootCertificate = AbstractX509Test.generateTestCertificate(ROOT_SUBJECTDN, idpPair);
        CertificateBuilder certBuilder = new CertificateBuilder(clientPair, idpPair.getPrivate(), rootCertificate, CERTIFICATE_SUBJECTDN);
        clientCertificates = new X509Certificate[]
                {
                    certBuilder.addSubjectAltNameExtension("example").build(),
                    rootCertificate
                };
    }

    @Before
    public void startup() throws Exception {
        MockitoAnnotations.initMocks(this);

        ValidateX509CertificateUsername temp = new ValidateX509CertificateUsername();
        nullCertificateResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "X509 Client certificate is missing.");
        configurationIsMissingResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Configuration is missing.");
        invalidDatesResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request",
                String.format("Certificate validation's failed. The reason: \"%s\"", null));
        nullUserIdentityResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Unable to extract user identity from specified certificate");
        invalidUserResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request",
                String.format("X509 certificate authentication's failed. Reason: \"%s\"", null));
        invalidUserCredentialsResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
        accountDisabledResponse = temp.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Account disabled");
        accountTemporarilyDisabledResponse = temp.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Account temporarily disabled");

        doReturn(context).when(flowContext).getHttpRequest();
        doReturn(user).when(flowContext).getUser();
        doReturn(events).when(flowContext).getEvent();
        doReturn(clientSession).when(flowContext).getClientSession();
        doReturn(null).when(events).user(any(UserModel.class));
        doNothing().when(flowContext).failure(any(AuthenticationFlowError.class), any(Response.class));
        doNothing().when(flowContext).success();
        doReturn(config).when(flowContext).getAuthenticatorConfig();
        doNothing().when(flowContext).setUser(any());
        doReturn(null).when(config).getConfig();
        doNothing().when(clientSession).setNote(any(),any());
        doReturn(realm).when(flowContext).getRealm();
        doReturn(bruteForceProtector).when(flowContext).getProtector();
        doReturn(clientCertificates).when(context).getAttribute(eq(ValidateX509CertificateUsername.JAVAX_SERVLET_REQUEST_X509_CERTIFICATE));
        doReturn(null).when(events).detail(any(), any());
        doReturn(true).when(user).isEnabled();
        doReturn(false).when(realm).isBruteForceProtected();

        doReturn(mockValidator).when(validatorBuilder).build(any());
        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(validatorBuilder).when(authenticator).certificateValidationParameters(any());
        doReturn(userIdModelMapper).when(authenticator).getUserIdentityToModelMapper(any());
    }

    @Test
    public void testUserIdentityFromSubjectDN_CN() throws Exception {

        HashMap<String,String> properties = new HashMap<>();
        properties.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN_CN);
        doReturn(properties).when(config).getConfig();

        doReturn(user).when(userIdModelMapper).find(any(),eq("username"));

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username"));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();

        verify(userIdModelMapper).find(any(), eq("username"));
    }

    @Test
    public void testUserIdentityFromSubjectDN_Email() throws Exception {

        HashMap<String,String> properties = new HashMap<>();
        properties.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN_EMAIL);
        doReturn(properties).when(config).getConfig();

        doReturn(user).when(userIdModelMapper).find(any(),eq("username@example.com"));

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username@example.com"));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();

        verify(userIdModelMapper).find(any(), eq("username@example.com"));
    }

    @Test
    public void testUserIdentityFromSubjectDN_RegularExpression() throws Exception {

        HashMap<String,String> properties = new HashMap<>();
        properties.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_SUBJECTDN);
        properties.put(REGULAR_EXPRESSION, "(.*?)(?:$)");
        doReturn(properties).when(config).getConfig();

        doReturn(user).when(userIdModelMapper).find(any(),eq("CN="+CERTIFICATE_SUBJECTDN));

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("CN="+CERTIFICATE_SUBJECTDN));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();

        verify(userIdModelMapper).find(any(), eq("CN="+CERTIFICATE_SUBJECTDN));
    }

    @Test
    public void testUserIdentityFromIssuerDN_CN() throws Exception {

        HashMap<String,String> properties = new HashMap<>();
        properties.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_ISSUERDN_CN);
        doReturn(properties).when(config).getConfig();

        doReturn(user).when(userIdModelMapper).find(any(),eq("IDP"));

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("IDP"));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();

        verify(userIdModelMapper).find(any(), eq("IDP"));
    }

    @Test
    public void testUserIdentityFromIssuerDN_Email() throws Exception {

        HashMap<String,String> properties = new HashMap<>();
        properties.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_ISSUERDN_EMAIL);
        doReturn(properties).when(config).getConfig();

        doReturn(user).when(userIdModelMapper).find(any(),eq("issuer@example.org"));

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("issuer@example.org"));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();

        verify(userIdModelMapper).find(any(), eq("issuer@example.org"));
    }

    @Test
    public void testUserIdentityFromIssuerDN_RegularExpression() throws Exception {

        HashMap<String,String> properties = new HashMap<>();
        properties.put(MAPPING_SOURCE_SELECTION, MAPPING_SOURCE_CERT_ISSUERDN);
        properties.put(REGULAR_EXPRESSION, "(.*?)(?:$)");
        doReturn(properties).when(config).getConfig();

        doReturn(user).when(userIdModelMapper).find(any(),eq("CN="+ROOT_SUBJECTDN));

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("CN="+ROOT_SUBJECTDN));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();

        verify(userIdModelMapper).find(any(), eq("CN="+ROOT_SUBJECTDN));
    }

}
