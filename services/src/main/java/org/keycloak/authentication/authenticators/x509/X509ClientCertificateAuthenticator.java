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

package org.keycloak.authentication.authenticators.x509;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.services.ServicesLogger;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Map;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateAuthenticator extends AbstractX509ClientCertificateAuthenticator {

    protected static ServicesLogger logger = ServicesLogger.ROOT_LOGGER;


    @Override
    public void close() {

    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("[X509ClientCertificateAuthenticator:authenticate]");

        try {

            dumpContainerAttributes(context);

            X509Certificate[] certs = getCertificateChain(context);
            if (certs == null || certs.length == 0) {
                // No x509 client cert, fall through and
                // continue processing the rest of the authentication flow
                logger.info("[X509ClientCertificateAuthenticator:authenticate] x509 client certificate is not available for mutual SSL.");
                context.attempted();
                return;
            }

            Map<String, String> parameters = null;

            AuthenticatorConfigModel config;
            if ((config = context.getAuthenticatorConfig()) != null) {
                parameters = config.getConfig();
            }
            if (parameters == null) {
                logger.warn("[X509ClientCertificateAuthenticator:authenticate] x509 Client Certificate Authentication configuration is not available.");
                context.attempted();
                return;
            }

            // Validate X509 client certificate
            try {
                certificateValidationParameters(parameters)
                        .x509(certs)
                        .validDates()
                        .validCertificateChain();
            }
            catch(GeneralSecurityException e) {
                logger.errorf("[X509ClientCertificateAuthenticator:authenticate] Exception: %s", e.getMessage());
                // TODO use specific locale to load error messages
                String errorMessage = String.format("Certificate validation's failed. The reason: \"%s\"", e.getMessage());
                // TODO is this the best to display an error?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }
            catch(IOException e) {
                logger.errorf("[X509ClientCertificateAuthenticator:authenticate] Exception: %s", e.getMessage());
                // TODO use specific locale to load error messages
                String errorMessage = String.format("Certificate validation failed due to an I/O error. The reason: \"%s\"", e.getMessage());
                // TODO is this the best to display an error?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }

            Object userIdentity = UserIdentityExtractorBuilder.fromConfig(parameters).extractUserIdentity(certs);
            if (userIdentity == null) {
                logger.warnf("[X509ClientCertificateAuthenticator:authenticate] Unable to extract user identity from certificate.");
                // TODO use specific locale to load error messages
                String errorMessage = "Unable to extract user identity from specified certificate";
                // TODO is this the best to display an error?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                return;
            }

            UserModel user;
            try {
                user = UserIdentityToModelMapperBuilder.fromConfig(parameters)
                        .find(context, userIdentity);
            }
            catch(ModelDuplicateException e) {
                logger.modelDuplicateException(e);
                String errorMessage = String.format("X509 certificate authentication's failed. Reason: \"%s\"", e.getMessage());
                // TODO is this the best to display an error?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }

            if (invalidUser(context, user)) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed. Reason: Invalid user";
                // TODO is this the best to display an error?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),errorMessage));
                context.attempted();
                return;
            }

            if (!userEnabled(context, user)) {
                context.getEvent().user(user);
                context.getEvent().error(Errors.USER_DISABLED);
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed. Reason: User is disabled";
                // TODO is this the best to display an error?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }
            if (context.getRealm().isBruteForceProtected()) {
                if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {
                    context.getEvent().user(user);
                    context.getEvent().error(Errors.USER_TEMPORARILY_DISABLED);
                    // TODO use specific locale to load error messages
                    String errorMessage = "X509 certificate authentication's failed. Reason: User is temporarily disabled. Contact administrator";
                    // TODO is this the best to display an error?
                    context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                    context.attempted();
                    return;
                }
            }
            context.setUser(user);
            // FIXME calling forceChallenge was the only way to display
            // a form to let users either choose the user identity from certificate
            // or to ignore it and proceed to a normal login screen. Attempting
            // to call the method "challenge" results in a wrong/unexpected behavior.
            // The question is whether calling "forceChallenge" here is ok from
            // the design viewpoint?
            context.forceChallenge(createSuccessResponse(context, certs[0].getSubjectDN().getName()));
            // Do not set the flow status yet, we want to display a form to let users
            // choose whether to accept the identity from certificate or to specify username/password explicitly
            ////context.success();
        }
        catch(Exception e) {
            logger.errorf("[X509ClientCertificateAuthenticator:authenticate] Exception: %s", e.getMessage());
            context.attempted();
        }
    }

    private Response createErrorResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         String errorMessage) {

        return createResponse(context, subjectDN, false, errorMessage);
    }

    private Response createSuccessResponse(AuthenticationFlowContext context,
                                           String subjectDN) {
        return createResponse(context, subjectDN, true, null);
    }

    private Response createResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         boolean isUserEnabled,
                                         String errorMessage) {

        LoginFormsProvider form = context.form();
        if (errorMessage != null && errorMessage.trim().length() > 0) {
            form.setError(errorMessage);
        }

        // FIXME BAD! Do not use absolute path to the javascript resource that includes keycloak's current build number.
        // What is the right way to add and reference javscript resources?
        form.addScript("/auth/resources/2.1.0-snapshot/login/keycloak/scripts/timedLogin.js");

        return form
                .setAttribute("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user")
                .setAttribute("subjectDN", subjectDN)
                .setAttribute("isUserEnabled", isUserEnabled)
                .createForm("login-x509-info.ftl");
    }

    private void dumpContainerAttributes(AuthenticationFlowContext context) {

        Enumeration<String> attributeNames = context.getHttpRequest().getAttributeNames();
        while(attributeNames.hasMoreElements()) {
            String a = attributeNames.nextElement();
            logger.infof("[X509ClientCertificateAuthenticator:dumpContainerAttributes] \"%s\"", a);
        }
    }

    private boolean userEnabled(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            return false;
        }
        return true;
    }

    private boolean invalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            return true;
        }
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("[X509ClientCertificateAuthenticator:action]");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.clearUser();
            context.attempted();
            return;
        }
        if (context.getUser() != null) {
            context.success();
            return;
        }
        context.attempted();
    }
}
