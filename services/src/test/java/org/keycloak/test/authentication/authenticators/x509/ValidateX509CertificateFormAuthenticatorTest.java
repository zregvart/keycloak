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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.UserIdentityExtractor;
import org.keycloak.authentication.authenticators.x509.UserIdentityToModelMapper;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.*;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/14/2016
 */

public class ValidateX509CertificateFormAuthenticatorTest extends AbstractX509Test {

    private Response certificateValidationErrorResponse;
    @Spy private X509ClientCertificateAuthenticator authenticator;
    @Captor ArgumentCaptor<List<FormMessage>> setErrorCaptor;
    @Captor ArgumentCaptor<String> nameCaptor;
    @Captor ArgumentCaptor<String> valueCaptor;
    @Mock private EventBuilder events;
    @Mock private UserModel user;
    @Mock private ClientSessionModel clientSession;
    @Mock private HttpRequest context;
    @Mock private UserCredentialValueModel credentials;
    @Mock private AuthenticationFlowContext flowContext;
    @Mock private AuthenticatorConfigModel config;
    @Mock private UserIdentityExtractor userIdExtractor;
    @Mock private UserIdentityToModelMapper userIdModelMapper;
    @Mock private RealmModel realm;
    @Mock private BruteForceProtector bruteForceProtector;
    @Mock private LoginFormsProvider loginFormsProvider;
    @Mock private AuthenticationExecutionModel executionModel;
    @Spy private CertificateValidator.CertificateValidatorBuilder validatorBuilder;

    @FunctionalInterface
    public interface ConsumerThatThrows<T> {
        public void accept(T o) throws GeneralSecurityException;
    }

    @Before
    public void startup() throws Exception {
        MockitoAnnotations.initMocks(this);

        X509ClientCertificateAuthenticator temp = new X509ClientCertificateAuthenticator();
        //certificateValidationErrorResponse = temp.createErrorResponse()

        doReturn(context).when(flowContext).getHttpRequest();
        doReturn(user).when(flowContext).getUser();
        doReturn(events).when(flowContext).getEvent();
        doReturn(clientSession).when(flowContext).getClientSession();
        doReturn(null).when(events).user(any(UserModel.class));
        doNothing().when(flowContext).failure(any(AuthenticationFlowError.class), any(Response.class));
        doNothing().when(flowContext).success();
        doNothing().when(flowContext).attempted();
        doNothing().when(flowContext).challenge(any());
        doReturn(config).when(flowContext).getAuthenticatorConfig();
        doNothing().when(flowContext).setUser(any());
        doReturn(null).when(config).getConfig();
        doNothing().when(clientSession).setNote(any(),any());
        doReturn(realm).when(flowContext).getRealm();
        doReturn(bruteForceProtector).when(flowContext).getProtector();
        doReturn(loginFormsProvider).when(flowContext).form();
        doReturn(executionModel).when(flowContext).getExecution();
        doReturn("execution_1").when(executionModel).getId();

        doReturn(new StringTokenizer("")).when(context).getAttributeNames();

        doReturn(validatorBuilder).when(authenticator).certificateValidationParameters(any());
        doReturn(userIdExtractor).when(authenticator).getUserIdentityExtractor(any());
        doReturn(userIdModelMapper).when(authenticator).getUserIdentityToModelMapper(any());
    }
    @Test
    public void testInvalidUserResponseWhenNullCertificate() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(null).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(flowContext).attempted();
    }
    @Test
    public void testInvalidUserResponseWhenNoCertificate() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(new X509Certificate[]{}).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(flowContext).attempted();
    }

    @Test
    public void testErrorResponseOnMissingConfiguration() {

        doReturn(clientCertificates).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events, never()).error(any());
        verify(flowContext).attempted();
    }

    private void testErrorResponseOnCertificateValidationException(ConsumerThatThrows<CertificateValidator> action) throws GeneralSecurityException {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        action.accept(mockValidator);

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();

        authenticator.authenticate(flowContext);

        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("Certificate validation's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }

    @Test
    public void testErrorResponseOnCertificateValidationBadRevocationStatus() throws Exception {

        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doThrow(GeneralSecurityException.class).when(mockValidator).checkRevocationStatus();
        });
    }

    @Test
    public void testErrorResponseOnCertificateValidationBadKeyUsage() throws Exception {

        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
            doThrow(GeneralSecurityException.class).when(mockValidator).validateKeyUsage();
        });
    }

    @Test
    public void testErrorResponseOnCertificateValidationBadExtendedKeyUsage() throws Exception {
        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
            doReturn(mockValidator).when(mockValidator).validateKeyUsage();
            doThrow(GeneralSecurityException.class).when(mockValidator).validateExtendedKeyUsage();
        });
    }

    @Test
    public void testErrorResponseOnGenericExceptionDuringCertValidation() throws Exception {
        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
            doThrow(Exception.class).when(mockValidator).validateKeyUsage();
        });
    }

    @Test
    public void testErrorResponseOnNullUserIdentity() throws GeneralSecurityException {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(null).when(userIdExtractor).extractUserIdentity(any());

        authenticator.authenticate(flowContext);

        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("Unable to extract user identity from specified certificate", setErrorCaptor.getValue().get(0).getMessage());
    }

    @Test
    public void testErrorResponseOnMissingUser() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(userIdModelMapper).find(any(),any());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
        verify(events).error(eq(Errors.USER_NOT_FOUND));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }

    @Test
    public void testErrorResponseOnModelDuplicateException() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doThrow(ModelDuplicateException.class).when(userIdModelMapper).find(any(),any());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
//        verify(events).error(eq(Errors.INVALID_USER_CREDENTIALS));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }
    @Test
    public void testErrorResponseOnUserIsDisable() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(false).when(user).isEnabled();

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
        verify(events).user(eq(user));
        verify(events).error(eq(Errors.USER_DISABLED));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }
    @Test
    public void testErrorResponseOnUserIsTemporarilyDisabled() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(true).when(user).isEnabled();
        doReturn(true).when(realm).isBruteForceProtected();
        doReturn(true).when(bruteForceProtector).isTemporarilyDisabled(any(),any(),any());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
        verify(events).user(eq(user));
        verify(events).error(eq(Errors.USER_TEMPORARILY_DISABLED));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }
    @Test
    public void testSuccessForceChallenge() throws Exception {

        final String userName = "some_user_name";

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(userName).when(userIdExtractor).extractUserIdentity(any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(userName).when(user).getUsername();
        doReturn(true).when(user).isEnabled();
        doReturn(false).when(realm).isBruteForceProtected();
        doReturn(loginFormsProvider).when(loginFormsProvider).setAttribute(anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq(userName));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq(userName));
        verify(events,never()).error(any());
        verify(flowContext).setUser(eq(user));
        verify(loginFormsProvider,never()).setErrors(any());
        verify(clientSession).setNote(eq(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION), eq("execution_1"));

        verify(loginFormsProvider,times(3)).setAttribute(nameCaptor.capture(), valueCaptor.capture());
        Assert.assertEquals("some_user_name", valueCaptor.getAllValues().get(0));
        Assert.assertEquals("CN=Client", valueCaptor.getAllValues().get(1));
        Assert.assertEquals(true, valueCaptor.getAllValues().get(2));

        verify(flowContext,atLeastOnce()).forceChallenge(any());

    }

    @Test
    public void testCancelLogin() throws Exception {

        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add("cancel","");
        doReturn(formData).when(context).getDecodedFormParameters();

        authenticator.action(flowContext);

        verify(flowContext).clearUser();
        verify(flowContext).attempted();
    }

    @Test
    public void testNoCancelOrValidUser() throws Exception {

        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        doReturn(formData).when(context).getDecodedFormParameters();
        doReturn(null).when(flowContext).getUser();

        authenticator.action(flowContext);

        verify(flowContext,never()).clearUser();
        verify(flowContext,never()).success();
        verify(flowContext).attempted();
    }

    @Test
    public void testSuccessfulLogin() throws Exception {

        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        doReturn(formData).when(context).getDecodedFormParameters();

        authenticator.action(flowContext);

        verify(flowContext,never()).clearUser();
        verify(flowContext,never()).attempted();
        verify(flowContext).success();
    }
}
