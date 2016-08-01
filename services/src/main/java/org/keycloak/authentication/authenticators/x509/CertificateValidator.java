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

import org.keycloak.services.ServicesLogger;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/30/2016
 */

public class CertificateValidator {

    private static final ServicesLogger logger = ServicesLogger.ROOT_LOGGER;

    X509Certificate[] _certChain;
    KeyStore _trustStore;
    CertificateValidator(X509Certificate[] certChain, KeyStore trustStore) {
        _certChain = certChain;
        _trustStore = trustStore;
    }
    CertificateValidator validDates() throws GeneralSecurityException {

        _certChain[0].checkValidity();
        return this;
    }
    CertificateValidator validCertificateChain() throws GeneralSecurityException {

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

                logger.debugf("[CertificateValidator:validCertificateChain] Algorithm: \"%s\", Issuer: \"%s\"",
                        _certChain[0].getSigAlgName(), _certChain[0].getIssuerDN().getName());

                trustManager.checkClientTrusted(_certChain, "RSA"/*certChain[0].getSigAlgName()*/);
                // If no exception is thrown, the certificate is valid
                break;
            }
        }
        return this;
    }

    static class CertificateValidatorBuilder {
        KeyStore _trustStore;
        CertificateValidatorBuilder(KeyStore trustStore) {
            _trustStore = trustStore;
        }

        CertificateValidator x509(X509Certificate[] certChain) {
            return new CertificateValidator(certChain, _trustStore);
        }
    }

    static class TrustStoreConfigurationBuilder {
        private String _trustStorePath;
        private String _trustStorePassword;
        private String _trustStoreType;

        TrustStoreConfigurationBuilder(String trustStorePath) {
            _trustStorePath = trustStorePath;
        }

        TrustStoreConfigurationBuilder withPassword(String trustStorePassword) {
            _trustStorePassword = trustStorePassword;
            return this;
        }

        TrustStoreConfigurationBuilder withType(String trustStoreType) {
            _trustStoreType = trustStoreType;
            return this;
        }

        CertificateValidatorBuilder build() throws GeneralSecurityException, IOException {

            KeyStore trustStore = null;

            if (_trustStoreType == null) {
                _trustStoreType = KeyStore.getDefaultType();
            }
            if (_trustStorePath != null && _trustStorePassword != null) {
                try {
                    FileInputStream myKeys = new FileInputStream(_trustStorePath);
                    trustStore = KeyStore.getInstance(_trustStoreType);
                    trustStore.load(myKeys, _trustStorePassword.toCharArray());
                    myKeys.close();
                }
                catch (Exception ex) {
                    logger.error("[TrustStoreConfigurationBuilder:build] Exception's been caught while trying to load a trust store", ex);
                    throw ex;
                }
            }

            return new CertificateValidatorBuilder(trustStore);
        }
    }

}
