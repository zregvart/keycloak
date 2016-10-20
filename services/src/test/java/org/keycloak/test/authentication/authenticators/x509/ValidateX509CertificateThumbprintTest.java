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
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.x509.CertificateThumbprint;
import org.keycloak.authentication.authenticators.x509.UserIdentityExtractor;
import org.keycloak.authentication.authenticators.x509.UserIdentityToModelMapper;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateThumbprint;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import javax.ws.rs.core.Response;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static java.util.Arrays.asList;
import static org.keycloak.authentication.authenticators.x509.ValidateX509CertificateThumbprint.CREDENTIAL_TYPE;
import static org.keycloak.authentication.authenticators.x509.ValidateX509CertificateThumbprint.JAVAX_SERVLET_REQUEST_X509_CERTIFICATE;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/14/2016
 */

public class ValidateX509CertificateThumbprintTest extends AbstractX509Test {

    private Response nullCertificateResponse;
    private Response unauthorizedResponse;
    private Response invalidCredentialsResponse;

    @Spy private ValidateX509CertificateThumbprint authenticator;
    @Mock private EventBuilder events;
    @Mock private UserModel user;
    @Mock private HttpRequest context;
    @Mock private AuthenticationFlowContext flowContext;
    @Mock private UserCredentialManager credentialManager;
    @Mock private KeycloakSession keycloakSession;
    @Mock private RealmModel realm;
    private UserCredentialModel credentials;
    private UserCredentialModel badCredentials;

    @Before
    public void startup() throws CertificateEncodingException, NoSuchAlgorithmException {
        MockitoAnnotations.initMocks(this);

        nullCertificateResponse = authenticator.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "X509 Client certificate is missing.");
        unauthorizedResponse = authenticator.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "X509 user credentials have not been set up.");
        invalidCredentialsResponse = authenticator.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");

        credentials = new UserCredentialModel();
        credentials.setType(CREDENTIAL_TYPE);
        credentials.setValue(CertificateThumbprint.computeDigest(clientCertificates));

        badCredentials = new UserCredentialModel();
        badCredentials.setType(CREDENTIAL_TYPE);
        badCredentials.setValue("badsignature");

        doReturn(context).when(flowContext).getHttpRequest();
        doReturn(user).when(flowContext).getUser();
        doReturn(events).when(flowContext).getEvent();
        doReturn(realm).when(flowContext).getRealm();
        doReturn(null).when(events).user(any(UserModel.class));
        doReturn(keycloakSession).when(flowContext).getSession();
        doReturn(credentialManager).when(keycloakSession).userCredentialManager();
        doNothing().when(flowContext).failure(any(AuthenticationFlowError.class), any(Response.class));
        doNothing().when(flowContext).success();
        doReturn(true).when(credentialManager).isValid(eq(realm),eq(user),eq(credentials));
        doReturn(false).when(credentialManager).isValid(eq(realm),eq(user),eq(badCredentials));
    }

    @Test
    public void testInvalidUserResponseWhenNullCertificate() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(nullCertificateResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(null).when(context).getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.INVALID_USER_CREDENTIALS));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(nullCertificateResponse));
    }

    @Test
    public void testInvalidUserResponseWhenNoCertificates() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(nullCertificateResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(new X509Certificate[] {}).when(context).getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.INVALID_USER_CREDENTIALS));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(nullCertificateResponse));
    }

    @Test
    public void testInvalidUserCredentialsResponseWhenMissingCredentials() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(unauthorizedResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(clientCertificates).when(context).getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.INVALID_USER_CREDENTIALS));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(unauthorizedResponse));
    }

    @Test
    public void testInvalidUserCredentialsResponseWhenCredentialsMismatch() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(invalidCredentialsResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(clientCertificates).when(context).getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);
        doReturn(badCredentials).when(authenticator).getCredentials(any());

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.INVALID_USER_CREDENTIALS));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(invalidCredentialsResponse));
    }

    @Test
    public void testCertificateThumbprintMatchSuccess() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(invalidCredentialsResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(clientCertificates).when(context).getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);
        doReturn(credentials).when(authenticator).getCredentials(any());

        authenticator.authenticate(flowContext);

        verify(events, never()).error(anyString());
        verify(flowContext, never()).failure(any(AuthenticationFlowError.class), any(Response.class));
        verify(events,never()).user(any(UserModel.class));
        verify(flowContext).success();
    }


}
