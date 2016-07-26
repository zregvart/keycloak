package org.keycloak.authentication.authenticators.x509;

import org.keycloak.services.ServicesLogger;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
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

        X509CertificateValidator getValidator() throws GeneralSecurityException, IOException {
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

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());

        tmf.init((KeyStore)null);

        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                X509TrustManager trustManager = (X509TrustManager)tm;

                logger.infof("[X509CertificateValidator:check] Certificate algorithm: \"%s\"",
                    certChain[0].getSigAlgName());

                trustManager.checkClientTrusted(certChain, null/*certChain[0].getSigAlgName()*/);
            }
        }
    }

}
