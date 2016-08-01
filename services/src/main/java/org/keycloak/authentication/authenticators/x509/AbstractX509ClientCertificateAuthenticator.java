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
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.services.ServicesLogger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/31/2016
 */

public abstract class AbstractX509ClientCertificateAuthenticator implements Authenticator {

    public static final String DEFAULT_ATTRIBUTE_NAME = "usercertificate";
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
    static final String MAPPING_SOURCE_CERT_SUBJECTDN = "Certificate SubjectDN";
    static final String MAPPING_SOURCE_CERT_ISSUERDN = "Certificate IssuerDN";
    static final String MAPPING_SOURCE_CERT_SERIALNUMBER = "Certificate Serial Number";
    static final String USER_MAPPER_SELECTION = "x509-cert-auth.mapper-selection";
    static final String USER_ATTRIBUTE_MAPPER = "Custom Attribute Mapper";
    static final String USERNAME_EMAIL_MAPPER = "Username or Email";
    static final String CUSTOM_ATTRIBUTE_NAME = "x509-cert-auth.mapper-selection.user-attribute-name";
    static final String TRUSTSTORE_PATH = "x509-cert-auth.truststore-path";
    static final String TRUSTSTORE_PASSWORD = "x509-cert-auth.truststore-password";
    static final String TRUSTSTORE_TYPE = "x509-cert-auth.truststore-type";
    static final String DEFAULT_MATCH_ALL_EXPRESSION = "(.*?)(?:$)";

    protected static String firstOrDefault(String value, String defaultValue) {

        return value != null && value.trim().length() > 0 ? value : defaultValue;
    }

    protected static class CertificateValidatorConfigBuilder {

        static CertificateValidator.CertificateValidatorBuilder fromConfig(Map<String, String> config) throws GeneralSecurityException, IOException {

            CertificateValidator.TrustStoreConfigurationBuilder builder = new CertificateValidator.TrustStoreConfigurationBuilder(firstOrDefault(System.getProperty(JAVAX_NET_SSL_TRUST_STORE),config.get(TRUSTSTORE_PATH)));
            return builder
                    .withPassword(firstOrDefault(System.getProperty(JAVAX_NET_SSL_TRUST_STORE_PASSWORD),config.get(TRUSTSTORE_PASSWORD)))
                    .withType(firstOrDefault(System.getProperty(JAVAX_NET_SSL_TRUST_STORE_TYPE),
                            firstOrDefault(config.get(TRUSTSTORE_TYPE), KeyStore.getDefaultType())))
                    .build();
        }
    }

    CertificateValidator.CertificateValidatorBuilder certificateValidationParameters(Map<String,String> parameters) throws GeneralSecurityException, IOException {
        return X509ClientCertificateAuthenticator.CertificateValidatorConfigBuilder.fromConfig(parameters);
    }

    protected static class UserIdentityExtractorBuilder {

        static UserIdentityExtractor fromConfig(Map<String,String> parameters) {

            String userIdentitySource = firstOrDefault(parameters.get(MAPPING_SOURCE_SELECTION),MAPPING_SOURCE_CERT_SUBJECTDN);
            String pattern = firstOrDefault(parameters.get(REGULAR_EXPRESSION),DEFAULT_MATCH_ALL_EXPRESSION);

            UserIdentityExtractor extractor = null;
            switch(userIdentitySource) {

                case MAPPING_SOURCE_CERT_SUBJECTDN:
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(pattern, certs -> certs[0].getSubjectDN().getName());
                    break;
                case MAPPING_SOURCE_CERT_ISSUERDN:
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(pattern, certs -> certs[0].getIssuerDN().getName());
                    break;
                case MAPPING_SOURCE_CERT_SERIALNUMBER:
                    extractor = UserIdentityExtractor.getPatternIdentityExtractor(pattern, certs -> certs[0].getSerialNumber().toString());
                    break;
                default:
                    logger.warnf("[UserIdentityExtractorBuilder:fromConfig] Unknown or unsupported user identity source: \"%s\"", userIdentitySource);
                    break;
            }
            return extractor;
        }
    }

    protected static class UserIdentityToModelMapperBuilder {

        static UserIdentityToModelMapper fromConfig(Map<String,String> parameters) {

            String mapperType = firstOrDefault(parameters.get(USER_MAPPER_SELECTION),USERNAME_EMAIL_MAPPER);
            String attributeName = firstOrDefault(parameters.get(CUSTOM_ATTRIBUTE_NAME),DEFAULT_ATTRIBUTE_NAME);

            UserIdentityToModelMapper mapper = null;
            switch (mapperType) {
                case USER_ATTRIBUTE_MAPPER:
                    mapper = UserIdentityToModelMapper.getUserIdentityToCustomAttributeMapper(attributeName);
                    break;
                case USERNAME_EMAIL_MAPPER:
                    mapper = UserIdentityToModelMapper.getUsernameOrEmailMapper();
                    break;
                default:
                    logger.warnf("[UserIdentityToModelMapperBuilder:fromConfig] Unknown or unsupported user identity mapper: \"%s\"", mapperType);
            }
            return mapper;
        }
    }

    @Override
    public void close() {

    }

    protected X509Certificate[] getCertificateChain(AuthenticationFlowContext context) {
        // Get a x509 client certificate
        X509Certificate[] certs = (X509Certificate[]) context.getHttpRequest().getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);

        if (certs != null) {
            for (X509Certificate cert : certs) {
                logger.infof("[X509ClientCertificateAuthenticator:getCertificateChain] \"%s\"", cert.getSubjectDN().getName());
            }
        }

        return certs;
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
