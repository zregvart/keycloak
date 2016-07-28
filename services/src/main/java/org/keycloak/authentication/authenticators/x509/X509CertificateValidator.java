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

import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.keycloak.services.ServicesLogger;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Map;

import static org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator.*;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/16/2016
 */

public class X509CertificateValidator {

    private static ServicesLogger logger = ServicesLogger.ROOT_LOGGER;
    private boolean _enableCRLChecking = false;
    private boolean _enableCRLDP = false;
    private boolean _enableOCSPChecking = false;
    private String _ocspResponderUri;
    private int _maximumCrtPathDepth = -1;
    private KeyStore _trustStore = null;

    public static class CertificateValidatorBuilder {

        protected static ServicesLogger logger = ServicesLogger.ROOT_LOGGER;

        private X509CertificateValidator _validator;

        public CertificateValidatorBuilder(X509CertificateValidator validator) {
            _validator = validator;
        }
        CertificateValidatorBuilder enableCRLDP(boolean value) {
            _validator.setEnableCRLDistributionPoint(value);
            return this;
        }
        CertificateValidatorBuilder enableCRL() {
            _validator.setEnableCRLChecking(true);
            return this;
        }
        CertificateValidatorBuilder disableCRL() {
            _validator.setEnableCRLChecking(false);
            return this;
        }
        CertificateValidatorBuilder disableCRLDP() {
            _validator.setEnableCRLDistributionPoint(false);
            return this;
        }
        CertificateValidatorBuilder enableOCSP() {
            _validator.setEnableOnlineCertificateStatusProtocol(true);
            return this;
        }
        CertificateValidatorBuilder disableOCSP() {
            _validator.setEnableOnlineCertificateStatusProtocol(false);
            return this;
        }
        CertificateValidatorBuilder responderUri(String responderUri) {
            if (responderUri != null && responderUri.trim().length() != 0) {
                _validator.setOnlineCertificateStatusProtocolResponderUri(responderUri);
            }
            return this;
        }

        TrustStoreBuilder trustStore() {
            return new TrustStoreBuilder(_validator);
        }

        X509CertificateValidator getValidator() throws GeneralSecurityException, IOException {
            return _validator;
        }
    }

    public static class TrustStoreBuilder {

        private String _trustStorePath;
        private String _trustStorePassword;
        private String _trustStoreType;
        private X509CertificateValidator _validator;

        public TrustStoreBuilder(X509CertificateValidator validator) {
            _validator = validator;
        }

        TrustStoreBuilder path(String trustStorePath) {
            logger.debugf("[CertificateValidatorBuilder:trustStorePath] \"%s\"", trustStorePath);
            _trustStorePath = trustStorePath;
            return this;
        }

        TrustStoreBuilder password(String trustStorePassword) {
            logger.debugf("[CertificateValidatorBuilder:trustStorePassword] \"%s\"", trustStorePassword);
            _trustStorePassword = trustStorePassword;
            return this;
        }

        TrustStoreBuilder type(String trustStoreType) {
            logger.debugf("[CertificateValidatorBuilder:trustStoreType] \"%s\"", trustStoreType);
            _trustStoreType = trustStoreType;
            return this;
        }

        X509CertificateValidator getValidator() throws GeneralSecurityException, IOException {

            KeyStore trustStore;

            if (_trustStoreType == null) {
                _trustStoreType = KeyStore.getDefaultType();
            }
            if (_trustStorePath != null && _trustStorePassword != null) {
                try {
                    FileInputStream myKeys = new FileInputStream(_trustStorePath);
                    trustStore = KeyStore.getInstance(_trustStoreType);
                    trustStore.load(myKeys, _trustStorePassword.toCharArray());
                    myKeys.close();

                    _validator.setTrustStore(trustStore);
                }
                catch (Exception ex) {
                    logger.error("[CertificateValidatorBuilder:getValidator] Exception's been caught while trying to load a trust store", ex);
                }
            }

            return _validator;
        }
    }

    public static CertificateValidatorBuilder fromConfig(Map<String, String> parameters) {

        X509CertificateValidator validator = new X509CertificateValidator();
        CertificateValidatorBuilder builder = new CertificateValidatorBuilder(validator);

        String crlDP;
        if ((crlDP = parameters.get(ENABLE_CRLDP)) == null) {
            crlDP = "false";
        }

        String ocspResponderUri = parameters.get(OCSPRESPONDER_URI);

        String certRevocationMethod;
        if ((certRevocationMethod = parameters.get(CERTIFICATE_CHECK_REVOCATION_METHOD)) == null) {
            certRevocationMethod = NO_CERT_CHECKING;
        }
        switch(certRevocationMethod.toLowerCase()) {
            case NO_CERT_CHECKING:
                builder.disableCRL().disableCRLDP().disableOCSP();
                break;

            case ENABLE_CRL:
                builder.enableCRL().enableCRLDP(Boolean.parseBoolean(crlDP)).disableOCSP();
                break;

            case ENABLE_OCSP:
                builder.enableOCSP().disableCRL().responderUri(ocspResponderUri);
                break;
        }

        String maxCertPathDepth;
        if ((maxCertPathDepth = parameters.get(MAXCERTPATHDEPTH)) != null) {
            validator.setMaximumCertPathDepth(Integer.parseInt(maxCertPathDepth));
        }

        return builder;
    }


    protected void setTrustStore(KeyStore trustStore) {
        _trustStore = trustStore;
    }

    /**
     * Enables or disables Certificate Revocation List checking
     * @param enable
     */
    public void setEnableCRLChecking(boolean enable) {
        _enableCRLChecking = enable;
    }

    /**
     * Enables Certificate Revocation List Distribution Point suppoer.
     * @param enable
     */
    public void setEnableCRLDistributionPoint(boolean enable) {
        _enableCRLDP = enable;
    }

    /**
     * Enables Online Certificate Status Protocol (OCSP) support
     * @param enable
     */
    public void setEnableOnlineCertificateStatusProtocol(boolean enable) {
        _enableOCSPChecking = enable;
    }

    /**
     * Sets OCSP Responder Uri
     * @param uri
     */
    public void setOnlineCertificateStatusProtocolResponderUri(String uri) {
        _ocspResponderUri = uri;
    }

    /**
     * Maximum number of intermediate certificates in a certificate chain (-1 is unlimited, default)
     * @param value
     */
    public void setMaximumCertPathDepth(int value) {
        _maximumCrtPathDepth = value;
    }

    /**
     * Validates the certificate chain.
     * @param certChain X509 Client certificate chain
     */
    public void check(X509Certificate[] certChain) throws GeneralSecurityException {

        certChain[0].checkValidity();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());

        if (_trustStore == null) {
            // Initialize trust manager factory with a default trust store
            tmf.init((KeyStore) null);
        }
        else {
            tmf.init(_trustStore);
        }

        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                X509TrustManager trustManager = (X509TrustManager)tm;

                dumpAcceptedIssuers(trustManager.getAcceptedIssuers());

                logger.debugf("[X509CertificateValidator:check] Algorithm: \"%s\", Issuer: \"%s\"",
                    certChain[0].getSigAlgName(), certChain[0].getIssuerDN().getName());

                trustManager.checkClientTrusted(certChain, "RSA"/*certChain[0].getSigAlgName()*/);
                // If no exception is thrown, the certificate is valid
                break;
            }
        }
    }

    private void dumpAcceptedIssuers(X509Certificate[] acceptedIssuers) {
        logger.debug("[X509CertificateValidator:dumpAcceptedIssuers] > list of accepted issuers");
        for (X509Certificate issuer : acceptedIssuers) {
            logger.debugf("[X509CertificateValidator:dumpAcceptedIssuers] accepted issuer: \"%s\"", issuer.getSubjectDN().getName());
        }
        logger.debug("[X509CertificateValidator:dumpAcceptedIssuers] < end of list of accepted issuers");
    }

}
