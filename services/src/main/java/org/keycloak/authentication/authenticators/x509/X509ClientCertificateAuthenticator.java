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
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Map;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateAuthenticator implements Authenticator {

    protected static ServicesLogger logger = ServicesLogger.ROOT_LOGGER;

    public static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";
    public static final String JAVAX_NET_SSL_TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword";
    public static final String JAVAX_NET_SSL_TRUST_STORE_TYPE = "javax.net.ssl.trustStoreType";
    public static final String JAVAX_SERVLET_REQUEST_X509_CERTIFICATE = "javax.servlet.request.X509Certificate";

    static final String REGULAR_EXPRESSION = "x509-cert-auth.regular-expression";
    static final String NO_CERT_CHECKING = "No CRL or OCSP Checking";
    static final String ENABLE_CRL = "CRL/CRLDP";
    static final String ENABLE_CRLDP = "x509-cert-auth.crldp-enabled";
    static final String ENABLE_OCSP = "OCSP/OCSP Responder";
    static final String OCSPRESPONDER_URI = "x509-cert-auth.ocsp-responder-uri";
    static final String MAXCERTPATHDEPTH = "x509-cert-auth.maximum-certpath-depth";
    static final String CERTIFICATE_CHECK_REVOCATION_METHOD = "x509-cert-auth.check-revocation-method";
    static final String MAPPING_SOURCE_SELECTION = "x509-cert-auth.mapping-source-selection";
    static final String MAPPING_SOURCE_CERT_SUBJECTDN = "x509 Client Certificate SubjectDN";
    static final String MAPPING_SOURCE_CERT_ISSUERDN = "x509 Client Certificate IssuerDN";
    static final String MAPPING_SOURCE_CERT_THUMBPRINT = "x509 Client Certificate Thumbprint";
    static final String MAPPING_SOURCE_CERT_SERIALNUMBER = "x509 Client Certificate Serial Number";
    static final String USER_MAPPER_SELECTION = "x509-cert-auth.mapper-selection";
    static final String USER_ATTRIBUTE_MAPPER = "Custom Attribute Mapper";
    static final String USER_PROPERTY_MAPPER = "Property Mapper";
    static final String USER_MAPPER_VALUE = "x509-cert-auth.mapper-selection.value";
    static final String SHOW_CHALLENGE_RESPONSE = "x509-cert-auth.show-challenge-response";

    static final class Result {

        private boolean _isCertificateValid = false;
        private boolean _isUserValid = false;
        private boolean _isUserEnabled = false;
        private String _subjectDN;
        public Result() {
        }

        public boolean isSuccess() {
            return _isCertificateValid && _isUserEnabled && _isUserEnabled;
        }
        public void setSubjectDN(String value) { _subjectDN = value; }
        public String getSubjectDN() { return _subjectDN; }
        public void setIsCertificateValid(boolean value) { _isCertificateValid = value; }
        public boolean getIsCertificateValid() { return _isCertificateValid; }
        public void setIsUserValid(boolean value) { _isUserValid = value; }
        public boolean getIsUserValid() { return _isUserValid; }
        public void setIsUserEnabled(boolean value) { _isUserEnabled = value; }
        public boolean getIsUserEnabled() { return _isUserEnabled; }
    }

    @Override
    public void close() {

    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("[X509ClientCertificateAuthenticator:authenticate]");

        X509ClientCertificateAuthenticator.Result result = new X509ClientCertificateAuthenticator.Result();
        boolean forceChallenge = false;
        try {

            dumpContainerAttributes(context);

            X509Certificate[] certs = getCertificateChain(context);
            if (certs == null || certs.length == 0) {
                // No x509 client cert, fall through
                logger.info("[X509ClientCertificateAuthenticator:authenticate] x509 client certificate is not available for mutual SSL.");
                context.attempted();
                return;
            }

            Map<String, String> parameters = context.getAuthenticatorConfig().getConfig();
            if (parameters == null) {
                logger.warn("[X509ClientCertificateAuthenticator:authenticate] x509 Client Certificate Authentication configuration is not available.");
                context.attempted();
                return;
            }

            if (parameters.containsKey(SHOW_CHALLENGE_RESPONSE)) {
                forceChallenge = Boolean.parseBoolean(parameters.get(SHOW_CHALLENGE_RESPONSE));
            }

            // Initialize certificate validation from configuration and validate the client certificate
            X509CertificateValidator.fromConfig(parameters)
                    .trustStore()
                    .path(System.getProperty(JAVAX_NET_SSL_TRUST_STORE))
                    .password(System.getProperty(JAVAX_NET_SSL_TRUST_STORE_PASSWORD))
                    .type(System.getProperty(JAVAX_NET_SSL_TRUST_STORE_TYPE))
                    .getValidator().check(certs);

            // TODO: x509 certificate mapping to the user needs to be more flexible.
            // See the example at:
            // https://docops.ca.com/ca-single-sign-on-12-52-sp1/en/configuring/policy-server-configuration/certificate-mapping-for-x-509-client-certificate-authentication-schemes
            // To locate a user entry the following mappings can be supported:
            // - A single attribute to user (like the emailAddress to user)
            // - a custom mapping expression
            // - Subject DN to user name
            // - IssuerDN to user (?)
            //
            // - Serial number ot user:
            //     user.attribute["serialNumber"]=${serialNumber}
            // - multiple attributes of the same name to user
            //    For example, sn=234,sn=4532 can be mapping as:
            //     userId=${sn1},group=${sn2} -> User(userId=234, group=4532)
            // - Certificate thumbprint
            //      User password will be used to store certificate thumbprint, or
            //      the user attribute 'cert.thumbprint' will be used to store certificate thumbprints (can be multiple)

            UserModel user;
            try {
                user = AbstractUserModelExtractor.fromConfig(parameters)
                        .find(context, certs);
            } catch (ModelDuplicateException ex) {
                // TODO Rework/rethink before pushing to keycloak main
                // the exception is thrown when there is a unique constraint
                // violation as in cases when attempting to create a user with
                // username that already exists. Here we do a simple user lookup
                // so is there really a need to handle this type of exception here?
                logger.modelDuplicateException(ex);
                context.attempted();
                return;
            }

            result.setSubjectDN(certs[0].getSubjectDN().getName());
            result.setIsCertificateValid(true);

            if (invalidUser(context, user)) {
                //context.attempted();
                //return;
                throw new GeneralSecurityException("User is invalid");
            }

            result.setIsUserValid(true);

            if (!userEnabled(context, user)) {
                //context.attempted();
                //return;
                throw new GeneralSecurityException("User is disabled");
            }

            result.setIsUserEnabled(true);

            context.setUser(user);
            //context.success();
        }
        catch(Exception e) {
            logger.errorf("[X509ClientCertificateAuthenticator:authenticate] Exception: %s", e.getMessage());
            context.attempted();
        }

        /*
        * TODO X509 authentication must be configured to work in different authentication flows.
        * regardless of a specific flow it is a part of. When authenticating users
        * with X509 certificates using Browser Flow, the authenticator may prompt
        * the user being authenticated to choose whether to continue with
        * the identity determined based on the contents of X509 certificate, or
        * to continue to the Login screen.
        * When using Direct Grant (grant_type=password), the X509 authenticator
        * must not prompt the user for any confirmation.
        * The way it is implemented now the administrator must configure X509 Cert
        * authenticator and enable "Require Authentication Confirmation" option
        * for Browser-based flows; the option must be disabled for Direct Grant-based flows.
        */
        if (forceChallenge) {
            Response challenge = createResponse(context, result);
            context.forceChallenge(challenge);
            return;
        }
        if (result.isSuccess() && context.getUser() != null) {
            context.success();
            return;
        }

        context.clearUser();

        if (context.getExecution().isRequired()) {
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }
        context.attempted();
    }

    private Response createResponse(AuthenticationFlowContext context, Result result) {

        LoginFormsProvider form = context.form();

        if (!result.getIsCertificateValid()) {
            form.setError("X509 Client certificate didn't pass validation checks");
        }
        else if (!result.getIsUserValid()) {
            form.setError("Invalid user credentials");
        }
        else if (!result.getIsUserEnabled()) {
            form.setError("The user account is disabled. Please contact the administrator");
        }

        return form
                .setAttribute("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user")
                .setAttribute("subjectDN", result.getSubjectDN())
                .setAttribute("isUserEnabled", result.getIsUserEnabled())
                .createForm("login-x509-info.ftl");
    }

    private X509Certificate[] getCertificateChain(AuthenticationFlowContext context) {
        // Get a x509 client certificate
        X509Certificate[] certs = (X509Certificate[]) context.getHttpRequest().getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);

        if (certs != null) {
            for (X509Certificate cert : certs) {
                logger.infof("[X509ClientCertificateAuthenticator:getCertificateChain] \"%s\"", cert.getSubjectDN().getName());
            }
        }

        return certs;
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

    @Override
    public boolean requiresUser() {
        logger.info("[X509ClientCertificateAuthenticator:requiresUser]");
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.infof("[X509ClientCertificateAuthenticator:configureFor] user: '%s'", user.getId());
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.infof("[X509ClientCertificateAuthenticator:setRequiredActions] user: '%s'", user.getId());

    }
}
