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

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.events.Errors;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;

import javax.ws.rs.core.Response;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/29/2016
 */

public class ValidateX509CertificateThumbprint extends AbstractDirectGrantAuthenticator {

    public final static String PROVIDER_ID = "direct-grant-auth-x509-thumbprint";
    private static final ServicesLogger logger = ServicesLogger.ROOT_LOGGER;
    public static final String JAVAX_SERVLET_REQUEST_X509_CERTIFICATE = "javax.servlet.request.X509Certificate";
    public static final String CREDENTIAL_TYPE = "x509certificate_signature";

    @Override
    public String getHelpText() {
        return "Validates that X509 client certificate thumbprint matches the thumbprint of a X509 certificate associated with the user.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new LinkedList<>();
    }

    @Override
    public String getDisplayType() {
        return "X509/Validates Certificate Thumbprint";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        X509Certificate[] certs = getCertificateChain(context);
        if (certs == null || certs.length == 0) {
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "X509 Client certificate is missing.");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        UserCredentialValueModel cred = null;
        for (UserCredentialValueModel model : context.getUser().getCredentialsDirectly()) {
            if (model.getType().equals(CREDENTIAL_TYPE)) {
                cred = model;
                break;
            }
        }
        if (cred == null) {
            logger.errorf("[ValidateX509CertificateThumbprint:authenticate] Unable to find X509 certificate based credentials. Set up the X509 based user credentials first.");
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "X509 user credentials have not been set up.");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        String signature = computeDigest(certs);
        if (!cred.getValue().equals(signature)) {
            logger.errorf("[ValidateX509CertificateThumbprint:authenticate] The user certificate does not match the provided client certificate.");
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    private X509Certificate[] getCertificateChain(AuthenticationFlowContext context) {
        return (X509Certificate[]) context.getHttpRequest().getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);
    }

    static String computeDigest(X509Certificate[] certs) {

        try {
            return CertificateThumbprint.computeDigest(certs);
        }
        catch(NoSuchAlgorithmException ex) {
            logger.errorf("[ValidateX509CertificateThumbprint:computeDigest] %s", ex.toString());
        }
        catch(CertificateEncodingException ex) {
            logger.errorf("[ValidateX509CertificateThumbprint:computeDigest] %s", ex.toString());
        }
        return null;
    }
}
