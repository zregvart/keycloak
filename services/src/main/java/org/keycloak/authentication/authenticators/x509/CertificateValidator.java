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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.keycloak.services.ServicesLogger;
import sun.security.provider.certpath.OCSP;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.*;
/**
 * @author <a href="mailto:pnalyvayko@agi.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/30/2016
 */

public class CertificateValidator {

    private static final ServicesLogger logger = ServicesLogger.LOGGER;

    private static final String CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31";

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

    public static class LdapContext {
        private final String ldapFactoryClassName;

        public LdapContext() {
            ldapFactoryClassName = "com.sun.jndi.ldap.LdapCtxFactory";
        }

        public LdapContext(String ldapFactoryClassName) {
            this.ldapFactoryClassName = ldapFactoryClassName;
        }

        public String getLdapFactoryClassName() {
            return ldapFactoryClassName;
        }
    }

    public static abstract class CRLLoaderImpl {
        /**
         * Returns a collection of {@link X509CRL}
         * @return
         * @throws GeneralSecurityException
         */
        public abstract Collection<X509CRL> getX509CRLs() throws GeneralSecurityException;
    }

    public static class CRLLoaderProxy extends CRLLoaderImpl {
        private final X509CRL _crl;
        public CRLLoaderProxy(X509CRL crl) {
            _crl = crl;
        }
        public Collection<X509CRL> getX509CRLs() throws GeneralSecurityException {
            return Collections.singleton(_crl);
        }
    }

    public static class CRLFileLoader extends CRLLoaderImpl {

        private final String cRLPath;
        private final LdapContext ldapContext;

        public CRLFileLoader(String cRLPath) {
            this.cRLPath = cRLPath;
            ldapContext = new LdapContext();
        }

        public CRLFileLoader(String cRLPath, LdapContext ldapContext) {
            this.cRLPath = cRLPath;
            this.ldapContext = ldapContext;

            if (ldapContext == null)
                throw new NullPointerException("Context cannot be null");
        }
        public Collection<X509CRL> getX509CRLs() throws GeneralSecurityException {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<X509CRL> crlColl = null;

            if (cRLPath != null) {
                if (cRLPath.startsWith("http") || cRLPath.startsWith("https")) {
                    // load CRL using remote URI
                    try {
                        crlColl = loadFromURI(cf, new URI(cRLPath));
                    } catch (URISyntaxException e) {
                        logger.error(e.getMessage());
                    }
                } else if (cRLPath.startsWith("ldap")) {
                    // load CRL from LDAP
                    try {
                        crlColl = loadCRLFromLDAP(cf, new URI(cRLPath));
                    } catch(URISyntaxException e) {
                        logger.error(e.getMessage());
                    }
                } else {
                    // load CRL from file
                    crlColl = loadCRLFromFile(cf, cRLPath);
                }
            }
            if (crlColl == null || crlColl.size() == 0) {
                String message = String.format("Unable to load CRL from \"%s\"", cRLPath);
                throw new GeneralSecurityException(message);
            }
            return crlColl;
        }

        private Collection<X509CRL> loadFromURI(CertificateFactory cf, URI remoteURI) throws GeneralSecurityException {
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

        private Collection<X509CRL> loadCRLFromLDAP(CertificateFactory cf, URI remoteURI) throws GeneralSecurityException {
            Hashtable env = new Hashtable(11);
            env.put(Context.INITIAL_CONTEXT_FACTORY, ldapContext.getLdapFactoryClassName());
            env.put(Context.PROVIDER_URL, remoteURI.toString());

            try {
                DirContext ctx = new InitialDirContext(env);
                try {
                    Attributes attrs = ctx.getAttributes("");
                    Attribute cRLAttribute = attrs.get("certificateRevocationList;binary");
                    byte[] data = (byte[])cRLAttribute.get();
                    if (data == null || data.length == 0) {
                        throw new CertificateException(String.format("Failed to download CRL from \"%s\"", remoteURI.toString()));
                    }
                    X509CRL crl = loadFromStream(cf, new ByteArrayInputStream(data));
                    return Collections.singleton(crl);
                } finally {
                    ctx.close();
                }
            } catch (NamingException e) {
                logger.error(e.getMessage());
            } catch(IOException e) {
                logger.error(e.getMessage());
            }

            return Collections.emptyList();
        }

        private Collection<X509CRL> loadCRLFromFile(CertificateFactory cf, String relativePath) throws GeneralSecurityException {
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
        private X509CRL loadFromStream(CertificateFactory cf, InputStream is) throws IOException, CRLException {
            DataInputStream dis = new DataInputStream(is);
            X509CRL crl = (X509CRL)cf.generateCRL(dis);
            dis.close();
            return crl;
        }
    }


    X509Certificate[] _certChain;
    int _keyUsageBits;
    List<String> _extendedKeyUsage;
    boolean _crlCheckingEnabled;
    boolean _crldpEnabled;
    CRLLoaderImpl _crlLoader;
    boolean _ocspEnabled;
    String _responderUri;

    public CertificateValidator() {

    }
    protected CertificateValidator(X509Certificate[] certChain,
                         int keyUsageBits, List<String> extendedKeyUsage,
                                   boolean cRLCheckingEnabled,
                                   boolean cRLDPCheckingEnabled,
                                   CRLLoaderImpl crlLoader,
                                   boolean oCSPCheckingEnabled,
                                   String oCSPResponderURI) {
        _certChain = certChain;
        _keyUsageBits = keyUsageBits;
        _extendedKeyUsage = extendedKeyUsage;
        _crlCheckingEnabled = cRLCheckingEnabled;
        _crldpEnabled = cRLDPCheckingEnabled;
        _crlLoader = crlLoader;
        _ocspEnabled = oCSPCheckingEnabled;
        _responderUri = oCSPResponderURI;
    }

    private static void validateKeyUsage(X509Certificate[] certs, int expected) throws GeneralSecurityException {
        boolean[] keyUsageBits = certs[0].getKeyUsage();
        if (keyUsageBits == null) {
            if (expected != 0) {
                String message = "Key usage extension is expected, but unavailable.";
                throw new GeneralSecurityException(message);
            }
            return;
        }

        boolean isCritical = false;
        Set critSet = certs[0].getCriticalExtensionOIDs();
        if (critSet != null) {
            isCritical = critSet.contains("2.5.29.15");
        }

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
        if (expectedEKU == null || expectedEKU.size() == 0) {
            logger.debug("Extended Key Usage validation is not enabled.");
            return;
        }
        List<String> extendedKeyUsage = certs[0].getExtendedKeyUsage();
        if (extendedKeyUsage == null) {
            String message = "Extended key usage extension is expected, but unavailable";
            throw new GeneralSecurityException(message);
        }

        boolean isCritical = false;
        Set critSet = certs[0].getCriticalExtensionOIDs();
        if (critSet != null) {
            isCritical = critSet.contains("2.5.29.37");
        }

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

    public CertificateValidator validateKeyUsage() throws GeneralSecurityException {
        validateKeyUsage(_certChain, _keyUsageBits);
        return this;
    }
    public CertificateValidator validateExtendedKeyUsage() throws GeneralSecurityException {
        validateExtendedKeyUsage(_certChain, _extendedKeyUsage);
        return this;
    }
    private static void checkRevocationUsingOCSP(X509Certificate[] certs, String responderUri) throws GeneralSecurityException {

        if (certs.length < 2) {
            // OCSP requires a responder certificate to verify OCSP
            // signed response.
            String message = "OCSP requires a responder certificate. OCSP cannot be used to verify the revocation status of self-signed certificates.";
            throw new GeneralSecurityException(message);
        }
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
                URI uri;
                try {
                    uri = new URI(responderUri);
                } catch (URISyntaxException e) {
                    String message = String.format("Unable to check certificate revocation status using OCSP.\n%s", e.getMessage());
                    throw new GeneralSecurityException(message);
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

    private static void checkRevocationStatusUsingCRL(X509Certificate[] certs, CRLLoaderImpl crLoader) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<X509CRL> crlColl = crLoader.getX509CRLs();
        if (crlColl != null && crlColl.size() > 0) {
            for (X509CRL it : crlColl) {
                if (it.isRevoked(certs[0])) {
                    String message = String.format("Certificate has been revoked, certificate's subject: %s", certs[0].getSubjectDN().getName());
                    logger.info(message);
                    throw new GeneralSecurityException(message);
                }
            }
        }
    }
    // See www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-cchain-and-verify-clr-with-bouncy-castle/
    private static List<String> getCRLDistributionPoints(X509Certificate cert) {
        byte[] data = cert.getExtensionValue(CRL_DISTRIBUTION_POINTS_OID);
        if (data == null)
            return new ArrayList<>();

        List<String> dps = new LinkedList<>();
        ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(data));
        try {
            DEROctetString octetString = (DEROctetString)is.readObject();
            byte[] octets = octetString.getOctets();

            ASN1InputStream is2 = new ASN1InputStream(new ByteArrayInputStream(octets));
            CRLDistPoint crlDP = CRLDistPoint.getInstance(is2.readObject());

            for (DistributionPoint dp : crlDP.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] names = GeneralNames.getInstance(dpn.getName()).getNames();
                    for (GeneralName gn : names) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(gn.getName()).getString();
                            dps.add(url);
                        }
                    }
                }
            }
        } catch (IOException | ClassCastException e) {
            logger.error(e.getMessage());
        }

        return dps;
    }

    private static void checkRevocationStatusUsingCRLDistributionPoints(X509Certificate[] certs) throws GeneralSecurityException {

        List<String> distributionPoints = getCRLDistributionPoints(certs[0]);
        if (distributionPoints == null || distributionPoints.size() == 0) {
            throw new GeneralSecurityException("Could not find any CRL distribution points in the certificate, unable to check the certificate revocation status using CRL/DP.");
        }
        for (String dp : distributionPoints) {
            logger.debugf("CRL Distribution point: \"%s\"", dp);
            checkRevocationStatusUsingCRL(certs, new CRLFileLoader(dp));
        }
    }

    public CertificateValidator checkRevocationStatus() throws GeneralSecurityException {
        if (!(_crlCheckingEnabled || _ocspEnabled)) {
            return this;
        }
        if (_crlCheckingEnabled) {
            if (!_crldpEnabled) {
                checkRevocationStatusUsingCRL(_certChain, _crlLoader /*"crl.pem"*/);
            } else {
                checkRevocationStatusUsingCRLDistributionPoints(_certChain);
            }
        }
        if (_ocspEnabled) {
            checkRevocationUsingOCSP(_certChain, _responderUri);
        }
        return this;
    }

    /**
     * Configure Certificate validation
     */
    public static class CertificateValidatorBuilder {
        // A hand written DSL that walks through successive steps to configure
        // instances of CertificateValidator type. The design is an adaption of
        // the approach described in http://programmers.stackexchange.com/questions/252067/learning-to-write-dsls-utilities-for-unit-tests-and-am-worried-about-extensablit

        int _keyUsageBits;
        List<String> _extendedKeyUsage;
        boolean _crlCheckingEnabled;
        boolean _crldpEnabled;
        CRLLoaderImpl _crlLoader;
        boolean _ocspEnabled;
        String _responderUri;

        public CertificateValidatorBuilder() {
            _extendedKeyUsage = new LinkedList<>();
            _keyUsageBits = 0;
        }

        public class KeyUsageValidationBuilder {

            CertificateValidatorBuilder _parent;
            KeyUsageValidationBuilder(CertificateValidatorBuilder parent) {
                _parent = parent;
            }

            public KeyUsageValidationBuilder enableDigitalSignatureBit() {
                _keyUsageBits |= 1 << KeyUsageBits.DIGITAL_SIGNATURE.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enablecRLSignBit() {
                _keyUsageBits |= 1 << KeyUsageBits.CRLSIGN.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enableDataEncriphermentBit() {
                _keyUsageBits |= 1 << KeyUsageBits.DATA_ENCIPHERMENT.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enableDecipherOnlyBit() {
                _keyUsageBits |= 1 << KeyUsageBits.DECIPHER_ONLY.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enableEnciphermentOnlyBit() {
                _keyUsageBits |= 1 << KeyUsageBits.ENCIPHERMENT_ONLY.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enableKeyAgreementBit() {
                _keyUsageBits |= 1 << KeyUsageBits.KEY_AGREEMENT.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enableKeyEnciphermentBit() {
                _keyUsageBits |= 1 << KeyUsageBits.KEY_ENCIPHERMENT.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enableKeyCertSign() {
                _keyUsageBits |= 1 << KeyUsageBits.KEYCERTSIGN.getInt();
                return this;
            }
            public KeyUsageValidationBuilder enableNonRepudiationBit() {
                _keyUsageBits |= 1 << KeyUsageBits.NON_REPUDIATION.getInt();
                return this;
            }

            public CertificateValidatorBuilder back() {
                return _parent;
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

        public class ExtendedKeyUsageValidationBuilder {

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

        public class RevocationStatusCheckBuilder {

            CertificateValidatorBuilder _parent;
            protected RevocationStatusCheckBuilder(CertificateValidatorBuilder parent) {
                _parent = parent;
            }

            public GotCRL cRLEnabled(boolean value) {
                _crlCheckingEnabled = value;
                return new GotCRL();
            }

            public class GotCRL {
                public GotCRLDP cRLDPEnabled(boolean value) {
                    _crldpEnabled = value;
                    return new GotCRLDP();
                }
            }

            public class GotCRLRelativePath {
                public GotOCSP oCSPEnabled(boolean value) {
                    _ocspEnabled = value;
                    return new GotOCSP();
                }
            }
            public class GotCRLDP {
                public GotCRLRelativePath cRLrelativePath(String value) {
                    if (value != null)
                        _crlLoader = new CRLFileLoader(value);
                    return new GotCRLRelativePath();
                }

                public GotCRLRelativePath cRLLoader(CRLLoaderImpl cRLLoader) {
                    if (cRLLoader != null)
                        _crlLoader = cRLLoader;
                    return new GotCRLRelativePath();
                }
            }

            public class GotOCSP {
                public CertificateValidatorBuilder oCSPResponderURI(String responderURI) {
                    _responderUri = responderURI;
                    return _parent;
                }
            }
        }

        public KeyUsageValidationBuilder keyUsage() {
            return new KeyUsageValidationBuilder(this);
        }

        public ExtendedKeyUsageValidationBuilder extendedKeyUsage() {
            return new ExtendedKeyUsageValidationBuilder(this);
        }

        public RevocationStatusCheckBuilder revocation() {
            return new RevocationStatusCheckBuilder(this);
        }

        public CertificateValidator build(X509Certificate[] certs) {
            if (_crlLoader == null) {
                 _crlLoader = new CRLFileLoader("");
            }
            return new CertificateValidator(certs, _keyUsageBits, _extendedKeyUsage,
                    _crlCheckingEnabled, _crldpEnabled, _crlLoader, _ocspEnabled, _responderUri);
        }
    }


}