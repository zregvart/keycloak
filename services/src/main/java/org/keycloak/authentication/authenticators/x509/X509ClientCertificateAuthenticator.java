package org.keycloak.authentication.authenticators.x509;

import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.freemarker.Templates;
import org.keycloak.forms.login.freemarker.model.RealmBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.theme.*;
import org.keycloak.utils.MediaType;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateAuthenticator implements Authenticator {

    protected static ServicesLogger logger = ServicesLogger.ROOT_LOGGER;

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

    @Override
    public void close() {

    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("[X509ClientCertificateAuthenticator:authenticate]");

        //X509CertificateLoginInfoBean loginInfo = new X509CertificateLoginInfoBean();
        try {

            dumpContainerAttributes(context);

            X509Certificate[] certs = getCertificateChain(context);
            if (certs == null || certs.length == 0) {
                // No x509 client cert, continue with the rest of authentication process
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

            // Initialize certificate validation from configuration and validate the client certificate
            X509CertificateValidator.fromConfig(parameters).getValidator().check(certs);

            //loginInfo.setIsCertificateValid(true);

            // TODO: x509 certificate mapping to the user shall be made more flexible.
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
                logger.modelDuplicateException(ex);
                context.attempted();
                return;
                //throw new GeneralSecurityException("There are multiple users found.");
            }

            if (invalidUser(context, user)) {
                context.attempted();
                return;
                //throw new GeneralSecurityException("User is invalid");
            }

            //loginInfo.setIsUserValid(true);

            if (!userEnabled(context, user)) {
                context.attempted();
                return;
                //throw new GeneralSecurityException("User is disabled");
            }

            //loginInfo.setIsUserEnabled(true);

            context.setUser(user);
            context.success();
        }
        catch(Exception e) {
            logger.error("[X509ClientCertificateAuthenticator:authenticate] Exception: "  + e.getMessage() + "\nStack trace:" + e.getStackTrace().toString());
            context.attempted();
        }
        //Response challenge = createResponse(context, loginInfo);
        //context.challenge(challenge);
    }

//    private Response createResponse(AuthenticationFlowContext context, X509CertificateLoginInfoBean loginInfo) {
//
//        MultivaluedMap<String,String> formData = new MultivaluedMapImpl<>();
//        formData.add("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user");
//        return context.form()
//                .setFormData(formData)
//                .setAttribute("isCertificateValid", loginInfo.getIsCertificateValid())
//                .setAttribute("isUserValid", loginInfo.getIsUserValid())
//                .setAttribute("isUserEnabled", loginInfo.getIsUserEnabled())
//                .createForm("login-x509-info.ftl");
//    }
//
    private X509Certificate[] getCertificateChain(AuthenticationFlowContext context) {
        // Get a x509 client certificate
        X509Certificate[] certs = (X509Certificate[]) context.getHttpRequest().getAttribute("javax.servlet.request.X509Certificate");

        if (certs != null) {
            for (X509Certificate cert : certs) {
                logger.info("[X509ClientCertificateAuthenticator:getCertificateChain] SubjectDN:" + cert.getSubjectDN().getName());
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
//        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
//        if (formData.containsKey("cancel")) {
//            context.clearUser();
//            context.attempted();
//            return;
//        }
//        if (context.getUser() != null) {
//            context.success();
//            return;
//        }
//        context.attempted();
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
