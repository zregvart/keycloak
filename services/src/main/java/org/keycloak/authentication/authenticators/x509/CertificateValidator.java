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
import sun.security.provider.certpath.OCSP;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/30/2016
 */

public class CertificateValidator {

    private static final ServicesLogger logger = ServicesLogger.ROOT_LOGGER;

    enum KeyUsageBits {
        DIGITAL_SIGNATURE(0, "digitalSignature"),
        NON_REPUDIATION(1, "nonRepudiation"),
        KEY_ENCIPHERMENT(2, "keyEncipherment"),
        DATA_ENCIPHERMENT(3, "dataEncipherment"),
        KEY_AGREEMENT(4, "keyAgreement"),
        KEYCERTSIGN(5, "keyCertSign"),
        CRLSIGN(6, "cRLSign"),
        ENCIPHERMENT_ONLY(7, "encipherOnly"),
        DECIPHER_ONLY(8, "decipherOnly");

        private int value;
        private String name;

        KeyUsageBits(int value, String name) {

            if (value < 0 || value > 8)
                throw new IllegalArgumentException("value");
            if (name == null || name.trim().length() == 0)
                throw new IllegalArgumentException("name");
            this.value = value;
            this.name = name.trim();
        }

        public int getInt() { return this.value; }
        public String getName() {  return this.name; }

        static public KeyUsageBits parse(String name) throws IllegalArgumentException, IndexOutOfBoundsException {
            if (name == null || name.trim().length() == 0)
                throw new IllegalArgumentException("name");

            for (KeyUsageBits bit : KeyUsageBits.values()) {
                if (bit.getName().equalsIgnoreCase(name))
                    return bit;
            }
            throw new IndexOutOfBoundsException("name");
        }

        static public KeyUsageBits fromValue(int value) throws IndexOutOfBoundsException {
            if (value < 0 || value > 8)
                throw new IndexOutOfBoundsException("value");
            for (KeyUsageBits bit : KeyUsageBits.values())
                if (bit.getInt() == value)
                    return bit;
            throw new IndexOutOfBoundsException("value");
        }
    }

    X509Certificate[] _certChain;
    KeyStore _trustStore;
    int _keyUsageBits;
    List<String> _extendedKeyUsage;
    boolean _crlCheckingEnabled;
    boolean _crldpEnabled;
    String _cRLRelativePath;
    boolean _ocspEnabled;
    String _responderUri;
    protected CertificateValidator(X509Certificate[] certChain, KeyStore trustStore,
                         int keyUsageBits, List<String> extendedKeyUsage,
                                   boolean cRLCheckingEnabled,
                                   boolean cRLDPCheckingEnabled,
                                   String cRLRelativePath,
                                   boolean oCSPCheckingEnabled,
                                   String oCSPResponderURI) {
        _certChain = certChain;
        _trustStore = trustStore;
        _keyUsageBits = keyUsageBits;
        _extendedKeyUsage = extendedKeyUsage;
        _crlCheckingEnabled = cRLCheckingEnabled;
        _crldpEnabled = cRLDPCheckingEnabled;
        _cRLRelativePath = cRLRelativePath;
        _ocspEnabled = oCSPCheckingEnabled;
        _responderUri = oCSPResponderURI;
    }

    CertificateValidator validDates() throws GeneralSecurityException {
        Date dt = new Date();
        _certChain[0].checkValidity(dt);
        return this;
    }

    private static void validateKeyUsage(X509Certificate[] certs, int expected) throws GeneralSecurityException {
        boolean[] keyUsageBits = certs[0].getKeyUsage();
        boolean isCritical = certs[0].getCriticalExtensionOIDs().contains("2.5.29.15");

        int n = expected;

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < keyUsageBits.length; i++, n >>= 1) {
            boolean value = keyUsageBits[i];
            if ((n & 1) == 1 && !value) {
                String message = String.format("Key Usage bit \'%s\' is not set.", CertificateValidator.KeyUsageBits.fromValue(i).getName());
                if (sb.length() > 0) sb.append("\n");
                sb.append(message);

                logger.warn(message);
            }
        }
        if (sb.length() > 0) {
            if (isCritical) {
                throw new GeneralSecurityException(sb.toString());
            }
        }
    }

    private static void validateExtendedKeyUsage(X509Certificate[] certs, List<String> expectedEKU) throws GeneralSecurityException {
        if (expectedEKU == null) {
            logger.debug("Extended Key Usage validation is not enabled.");
            return;
        }
        List<String> extendedKeyUsage = certs[0].getExtendedKeyUsage();
        boolean isCritical = certs[0].getCriticalExtensionOIDs().contains("2.5.29.37");

        List<String> ekuList = new LinkedList<>();
        extendedKeyUsage.forEach(s -> ekuList.add(s.toLowerCase()));

        for (String eku : expectedEKU) {
            if (!ekuList.contains(eku.toLowerCase())) {
                String message = String.format("Extended Key Usage \'%s\' is missing.", eku);
                if (isCritical) {
                    throw new GeneralSecurityException(message);
                }
                logger.warn(message);
            }
        }
    }

    CertificateValidator validateKeyUsage() throws GeneralSecurityException {
        validateKeyUsage(_certChain, _keyUsageBits);
        return this;
    }
    CertificateValidator validateExtendedKeyUsage() throws GeneralSecurityException {
        validateExtendedKeyUsage(_certChain, _extendedKeyUsage);
        return this;
    }
    CertificateValidator validateCertificatePath() throws GeneralSecurityException {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificates = new LinkedList<>();
        certificates.add(_certChain[0]);
        CertPath certPath = cf.generateCertPath(certificates);

        PKIXParameters params = new PKIXParameters(_trustStore);
        params.setRevocationEnabled(false);

        CertPathValidator pathValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());

        logger.debugf("PKIX certificate path validation params: %s", params.toString());

        pathValidator.validate(certPath, params);

        return this;
    }

    private static void checkRevocationUsingOCSP(X509Certificate[] certs, String responderUri) throws GeneralSecurityException {

        try {
            OCSP.RevocationStatus rs;

            if (responderUri == null || responderUri.trim().length() == 0) {
                // Obtains revocation status of a certificate using OCSP and assuming
                // most common defaults. If responderUri is not specified,
                // then OCS responder URI is retrieved from the
                // certificate's AIA extension.  The OCSP responder certificate is assumed
                // to be the issuer's certificate (or issued by the issuer CA).
                rs = OCSP.check(certs[0], certs[1]);
            }
            else {
                URI uri = null;
                try {
                    uri = new URI(responderUri);
                } catch (URISyntaxException e) {
                    String message = String.format("Unable to check certificate revocation status using OCSP.\n%s", e.getMessage());
                    new GeneralSecurityException(message);
                }
                logger.debugf("Responder URI \"%s\" will be used to verify revocation status of the certificate using OCSP", uri.toString());
                // Obtains the revocation status of a certificate using OCSP.
                // OCSP responder's certificate is assumed to be the issuer's certificate
                // certificate.
                // responderUri overrides the contents (if any) of the certificate's AIA extension
                rs = OCSP.check(certs[0], certs[1], uri, certs[1], null);
            }

            if (rs == null) {
                throw new GeneralSecurityException("Unable to check client revocation status using OCSP");
            }

            if (rs.getCertStatus() == OCSP.RevocationStatus.CertStatus.UNKNOWN) {
                throw new GeneralSecurityException("Unable to determine certificate's revocation status.");
            }
            else if (rs.getCertStatus() == OCSP.RevocationStatus.CertStatus.REVOKED) {

                StringBuilder sb = new StringBuilder();
                sb.append("Certificate's been revoked.");
                sb.append("\n");
                sb.append(String.format("Revocation reason: %s", rs.getRevocationReason().name()));
                sb.append("\n");
                sb.append(String.format("Revoked on: %s",rs.getRevocationTime().toString()));

                throw new GeneralSecurityException(sb.toString());
            }
        } catch (IOException e) {
            StringBuilder sb = new StringBuilder();
            sb.append(e.getMessage());

            StackTraceElement[] stackElements = e.getStackTrace();
            for (StackTraceElement se : stackElements) {
                sb.append("\n");
                sb.append(se.toString());
            }
            logger.error(sb.toString());

            throw new GeneralSecurityException(e.getMessage());
        }
    }

    static private X509CRL loadFromStream(CertificateFactory cf, InputStream is) throws IOException, CRLException {
        DataInputStream dis = new DataInputStream(is);
        X509CRL crl = (X509CRL)cf.generateCRL(dis);
        dis.close();
        return crl;
    }

    static private Collection<X509CRL> loadFromURI(CertificateFactory cf, URI remoteURI) throws GeneralSecurityException {
        try {
            logger.infof("Loading CRL from %s", remoteURI.toString());

            URLConnection conn = remoteURI.toURL().openConnection();
            conn.setDoInput(true);
            conn.setUseCaches(false);
            X509CRL crl = loadFromStream(cf, conn.getInputStream());
            return Collections.singleton(crl);
        }
        catch(IOException ex) {
            logger.errorf(ex.getMessage());
        }
        return Collections.emptyList();

    }

    static private Collection<X509CRL> loadCRLFromFile(CertificateFactory cf, String relativePath) throws GeneralSecurityException {
        try {
            String configDir = System.getProperty("jboss.server.config.dir");
            if (configDir != null) {
                File f = new File(configDir + File.separator + relativePath);
                if (f.isFile()) {
                    logger.infof("Loading CRL from %s", f.getAbsolutePath());

                    if (!f.canRead()) {
                        throw new IOException(String.format("Unable to read CRL from \"%path\"", f.getAbsolutePath()));
                    }
                    X509CRL crl = loadFromStream(cf, new FileInputStream(f.getAbsolutePath()));
                    return Collections.singleton(crl);
                }
            }
        }
        catch(IOException ex) {
            logger.errorf(ex.getMessage());
        }
        return Collections.emptyList();
    }
    private static void checkRevocationStatusUsingCRL(X509Certificate[] certs, String cRLPath) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<X509CRL> crlColl = null;

        if (cRLPath != null && (cRLPath.startsWith("http") || cRLPath.startsWith("https"))) {
            // load CRL using remote URI
            try {
                crlColl = loadFromURI(cf, new URI(cRLPath));
            } catch (URISyntaxException e) {
                logger.error(e.getMessage());
            }
        }
        else {
            // load CRL from file
            crlColl = loadCRLFromFile(cf, cRLPath);
        }
        if (crlColl != null && crlColl.size() > 0) {
            for (X509CRL it : crlColl) {
                if (it.isRevoked(certs[0])) {
                    String message = String.format("Certificate has been revoked, certificate's subject: %s", certs[0].getSubjectDN().getName());
                    logger.info(message);
                    throw new GeneralSecurityException(message);
                }
            }
        } else {
            String message = String.format("Unable to load CRL from \"%s\"", cRLPath);
            throw new GeneralSecurityException(message);
        }
    }

    CertificateValidator checkRevocationStatus() throws GeneralSecurityException {
        if (!(_crlCheckingEnabled || _crldpEnabled || _ocspEnabled)) {
            return this;
        }
        if (_crlCheckingEnabled || _crldpEnabled) {
            checkRevocationStatusUsingCRL(_certChain, _cRLRelativePath /*"crl.pem"*/);
        }
        if (_ocspEnabled) {
            checkRevocationUsingOCSP(_certChain, _responderUri);
        }
        return this;
    }

    /**
     * Configure Certificate validation
     */
    static class CertificateValidatorBuilder {
        // A hand written DSL that walks through successive steps to configure
        // instances of CertificateValidator type. The design is an adaption of
        // the approach described in http://programmers.stackexchange.com/questions/252067/learning-to-write-dsls-utilities-for-unit-tests-and-am-worried-about-extensablit

        int _keyUsageBits;
        List<String> _extendedKeyUsage;
        KeyStore _trustStore;
        boolean _crlCheckingEnabled;
        boolean _crldpEnabled;
        String _cRLRelativePath;
        boolean _ocspEnabled;
        String _responderUri;

        CertificateValidatorBuilder() {
            _extendedKeyUsage = new LinkedList<>();
            _keyUsageBits = 0;
            _trustStore = null;
        }

        class KeyUsageValidationBuilder {

            CertificateValidatorBuilder _parent;
            KeyUsageValidationBuilder(CertificateValidatorBuilder parent) {
                _parent = parent;
            }

            KeyUsageValidationBuilder enableDigitalSignatureBit() {
                _keyUsageBits |= 1 << KeyUsageBits.DIGITAL_SIGNATURE.getInt();
                return this;
            }
            KeyUsageValidationBuilder enablecRLSignBit() {
                _keyUsageBits |= 1 << KeyUsageBits.CRLSIGN.getInt();
                return this;
            }
            KeyUsageValidationBuilder enableDataEncriphermentBit() {
                _keyUsageBits |= 1 << KeyUsageBits.DATA_ENCIPHERMENT.getInt();
                return this;
            }
            KeyUsageValidationBuilder enableDecipherOnlyBit() {
                _keyUsageBits |= 1 << KeyUsageBits.DECIPHER_ONLY.getInt();
                return this;
            }
            KeyUsageValidationBuilder enableEnciphermentOnlyBit() {
                _keyUsageBits |= 1 << KeyUsageBits.ENCIPHERMENT_ONLY.getInt();
                return this;
            }
            KeyUsageValidationBuilder enableKeyAgreementBit() {
                _keyUsageBits |= 1 << KeyUsageBits.KEY_AGREEMENT.getInt();
                return this;
            }
            KeyUsageValidationBuilder enableKeyEnciphermentBit() {
                _keyUsageBits |= 1 << KeyUsageBits.KEY_ENCIPHERMENT.getInt();
                return this;
            }
            KeyUsageValidationBuilder enableKeyCertSign() {
                _keyUsageBits |= 1 << KeyUsageBits.KEYCERTSIGN.getInt();
                return this;
            }
            KeyUsageValidationBuilder enableNonRepudiationBit() {
                _keyUsageBits |= 1 << KeyUsageBits.NON_REPUDIATION.getInt();
                return this;
            }

            CertificateValidatorBuilder parse(String keyUsage) {
                if (keyUsage == null || keyUsage.trim().length() == 0)
                    return _parent;

                String[] strs = keyUsage.split("[,]");

                for (String s : strs) {
                    try {
                        KeyUsageBits bit = KeyUsageBits.parse(s.trim());
                        switch(bit) {
                            case CRLSIGN: enablecRLSignBit(); break;
                            case DATA_ENCIPHERMENT: enableDataEncriphermentBit(); break;
                            case DECIPHER_ONLY: enableDecipherOnlyBit(); break;
                            case DIGITAL_SIGNATURE: enableDigitalSignatureBit(); break;
                            case ENCIPHERMENT_ONLY: enableEnciphermentOnlyBit(); break;
                            case KEY_AGREEMENT: enableKeyAgreementBit(); break;
                            case KEY_ENCIPHERMENT: enableKeyEnciphermentBit(); break;
                            case KEYCERTSIGN: enableKeyCertSign(); break;
                            case NON_REPUDIATION: enableNonRepudiationBit(); break;
                        }
                    }
                    catch(IllegalArgumentException e) {
                        logger.warnf("Unable to parse key usage bit: \"%s\"", s);
                    }
                    catch(IndexOutOfBoundsException e) {
                        logger.warnf("Invalid key usage bit: \"%s\"", s);
                    }
                }

                return _parent;
            }
        }

        class ExtendedKeyUsageValidationBuilder {

            CertificateValidatorBuilder _parent;
            protected ExtendedKeyUsageValidationBuilder(CertificateValidatorBuilder parent) {
                _parent = parent;
            }

            public CertificateValidatorBuilder parse(String extendedKeyUsage) {
                if (extendedKeyUsage == null || extendedKeyUsage.trim().length() == 0)
                    return _parent;

                String[] strs = extendedKeyUsage.split("[,;:]]");
                for (String str : strs) {
                    _extendedKeyUsage.add(str.trim());
                }
                return _parent;
            }
        }

        class TrustStoreBuilder {

            private String _trustStorePath;
            private String _trustStorePassword;
            CertificateValidatorBuilder _parent;
            TrustStoreBuilder(CertificateValidatorBuilder parent) {
                _parent = parent;
            }

            GotTrustStorePath setPath(String trustStorePath) {
                _trustStorePath = trustStorePath;
                return new GotTrustStorePath();
            }

            class GotTrustStorePath {
                GotTrustStorePassword setPassword(String password) {
                    _trustStorePassword = password;
                    return new GotTrustStorePassword();
                }
            }

            class GotTrustStorePassword {
                CertificateValidatorBuilder setType(String type) throws Exception {
                    if (type == null) {
                        type = KeyStore.getDefaultType();
                    }
                    String javaHome = System.getProperty("java.home");
                    String path = _trustStorePath;
                    if (path == null || path.equalsIgnoreCase("NONE")) {
                        String sep = File.separator;
                        //
                        // Figure out a path to the default JVM trust store
                        //
                        File f = new File(javaHome + sep
                                + "lib" + sep
                                + "security" + sep
                                + "jssecacerts");
                        if (f.canRead()) {
                            path = f.getAbsolutePath();
                        }
                        else {
                            f = new File(javaHome + sep
                                        + "lib" + sep
                                        + "security" + sep
                                        + "cacerts");
                            path = f.getAbsolutePath();
                        }
                    }
                    _trustStore = loadTrustStoreFromFile(path, _trustStorePassword, type);
                    if (_trustStore == null) {
                        throw new IOException("Failed to load certificate trust store.");
                    }
                    return _parent;
                }

                private KeyStore loadTrustStoreFromFile(String path, String password, String type) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

                    KeyStore trustStore = null;

                    if (path != null && password != null) {
                        try {
                            logger.infof("Loading certificate trust store from \"%s\"", path);

                            String configDir = System.getProperty("jboss.server.config.dir");
                            if (configDir != null) {
                                File f = new File(path);
                                if (!f.isAbsolute()) {
                                    f = new File(configDir + File.separator + path);
                                }
                                if (f.canRead()) {
                                    FileInputStream myKeys = new FileInputStream(f.getAbsolutePath());
                                    trustStore = KeyStore.getInstance(type);
                                    trustStore.load(myKeys, password.toCharArray());
                                    myKeys.close();
                                }
                                else {
                                    throw new IOException(String.format("Unable to read a trust store \"%s\".", f.getAbsolutePath()));
                                }
                            }
                            else {
                                throw new IOException("Unable to resolve a path to the configuration directory.");
                            }
                        }
                        catch (Exception ex) {
                            logger.error("[TrustStoreBuilder:build] Exception's been caught while trying to load a trust store", ex);
                            throw ex;
                        }
                    }
                    return trustStore;
                }
            }
        }

        class RevocationStatusCheckBuilder {

            CertificateValidatorBuilder _parent;
            protected RevocationStatusCheckBuilder(CertificateValidatorBuilder parent) {
                _parent = parent;
            }

            GotCRL cRLEnabled(String value) {
                if (value != null)
                    _crlCheckingEnabled = Boolean.parseBoolean(value);
                return new GotCRL();
            }

            class GotCRL {
                GotCRLDP cRLDPEnabled(String value) {
                    if (value != null)
                        _crldpEnabled = Boolean.parseBoolean(value);
                    return new GotCRLDP();
                }
            }

            class GotCRLRelativePath {
                GotOCSP oCSPEnabled(String value) {
                    if (value != null)
                        _ocspEnabled = Boolean.parseBoolean(value);
                    return new GotOCSP();
                }
            }
            class GotCRLDP {
                GotCRLRelativePath cRLrelativePath(String value) {
                    if (value != null)
                        _cRLRelativePath = value;
                    return new GotCRLRelativePath();
                }
            }

            class GotOCSP {
                CertificateValidatorBuilder oCSPResponderURI(String responderURI) {
                    _responderUri = responderURI;
                    return _parent;
                }
            }
        }

        KeyUsageValidationBuilder keyUsage() {
            return new KeyUsageValidationBuilder(this);
        }

        ExtendedKeyUsageValidationBuilder extendedKeyUsage() {
            return new ExtendedKeyUsageValidationBuilder(this);
        }

        TrustStoreBuilder trustStore() {
            return new TrustStoreBuilder(this);
        }

        RevocationStatusCheckBuilder revocation() {
            return new RevocationStatusCheckBuilder(this);
        }

        CertificateValidator build(X509Certificate[] certs) {
            return new CertificateValidator(certs, _trustStore, _keyUsageBits, _extendedKeyUsage,
                    _crlCheckingEnabled, _crldpEnabled, _cRLRelativePath, _ocspEnabled, _responderUri);
        }
    }


}
