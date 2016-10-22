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

package org.keycloak.test.authentication.authenticators.x509;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.BeforeClass;
import org.keycloak.common.util.CertificateBuilder;
import org.keycloak.common.util.CertificateUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/14/2016
 */

public abstract class AbstractX509Test {
    public static final String SHA_1_WITH_RSA_ENCRYPTION = "SHA1WithRSAEncryption";
    public static final String BOUNCYCASTLE_PROVIDER = "BC";
    protected static X509Certificate rootCertificate;
    protected static X509Certificate[] serverCertificates;
    protected static X509Certificate[] clientCertificates;
    protected static X509Certificate[] clientCertificatesNonCriticalKeyUsage;
    protected static X509Certificate[] clientCertificatesNoKeyUsage;
    protected static KeyPair idpPair;
    protected static KeyPair clientPair;
    protected static URI cRLdistributionPoint;
    protected static URI ocspResponderUri;
    protected static URI mockServerURI;
    protected static int mockServerPort;

    static {
        mockServerPort = 1080;
        mockServerURI = URI.create(String.format("http://localhost:%d", mockServerPort));
    }

    public static X509Certificate generateTestCertificate(String subject, KeyPair pair) throws InvalidKeyException,
            NoSuchProviderException, SignatureException {

        X509Certificate certificate = null;
        try {
            certificate = CertificateUtils.generateV1SelfSignedCertificate(pair, subject);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return certificate;
    }

    @BeforeClass
    public static void setupCerts() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, CertificateEncodingException, MalformedURLException, URISyntaxException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        idpPair = generator.generateKeyPair();
        clientPair = generator.generateKeyPair();

        cRLdistributionPoint = new URL(mockServerURI.toURL(), "dp").toURI();
        ocspResponderUri = new URL(mockServerURI.toURL(), "ocsp").toURI();

        rootCertificate = generateTestCertificate("IDP", idpPair);
        clientCertificates = new X509Certificate[] {generateCertificate("Client", clientPair,
                idpPair.getPrivate(), rootCertificate),  rootCertificate};

        clientCertificatesNonCriticalKeyUsage = new X509Certificate[] {generateCertificateNonCriticalKeyUsage("Client", generator.generateKeyPair(),
                idpPair.getPrivate(), rootCertificate), rootCertificate};

        clientCertificatesNoKeyUsage = new X509Certificate[] {generateCertificateNoKeyUsage("Client", generator.generateKeyPair(),
                idpPair.getPrivate(), rootCertificate), rootCertificate};
    }

    private static X509Certificate generateCertificateNoKeyUsage(String subject, KeyPair pair, PrivateKey caPrivateKey, X509Certificate ca) {
        X509Certificate certificate = null;
        try {
            // Creates a V3 X509 certificate with the extensions:
            // - Subject Key
            // - Authority Key
            // - Basic Constraints
            // KeyUsage and ExtendedKeyUsage extensions are omitted
            certificate = new CertificateBuilder(pair, caPrivateKey, ca, subject)
                    .addCRLDistributionPointsExtension(cRLdistributionPoint)
                    .addOCSPResponderExtension(ocspResponderUri)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return certificate;
    }

    private static X509Certificate generateCertificateNonCriticalKeyUsage(String subject, KeyPair pair, PrivateKey caPrivateKey, X509Certificate ca) {
        X509Certificate certificate = null;
        try {
            // Creates a V3 X509 certificate with the extensions:
            // - Subject Key
            // - Authority Key
            // - Key Usage (digitalSignature, keyCertSign, cRLSign)
            // - Extended Key Usage (id_kp_emailProtection, id_kp_serverAuth)
            // - Basic Constraints
            // KeyUsage and ExtendedKeyUsage extensions are NOT critical.
            // Certificates with invalid key usage or invalid extended key usage
            // will still pass the certificate validation.
            certificate = new CertificateBuilder(pair, caPrivateKey, ca, subject)
                    .addKeyUsageExtension(false)
                    .addExtendedKeyUsageExtension(false)
                    .addCRLDistributionPointsExtension(cRLdistributionPoint)
                    .addOCSPResponderExtension(ocspResponderUri)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return certificate;
    }

    public static X509Certificate generateCertificate(String subject, KeyPair pair, PrivateKey caPrivateKey, X509Certificate ca) {
        X509Certificate certificate = null;
        try {
            // Creates a V3 X509 certificate with the extensions:
            // - Subject Key
            // - Authority Key
            // - Key Usage (digitalSignature, keyCertSign, cRLSign)
            // - Extended Key Usage (id_kp_emailProtection, id_kp_serverAuth)
            // - Basic Constraints
            // KeyUsage and ExtendedKeyUsage extensions are set to be critical
            // so that to force the methods validateKeyUsage and validateExtendedKeyUsage
            // of the CertificateValidator class throw a general security exception when there is a mismatch
            // between the certificate's values and the values specified by the validator.
            certificate = new CertificateBuilder(pair, caPrivateKey, ca, subject)
                    .addKeyUsageExtension(true)
                    .addExtendedKeyUsageExtension(true)
                    .addCRLDistributionPointsExtension(cRLdistributionPoint)
                    .addOCSPResponderExtension(ocspResponderUri)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return certificate;
    }

    /**
     * Creates a signed CRL with a single entry using the specified certificate.
     * @param caKey
     * @param caCert
     * @param revoked
     * @return
     * @throws OperatorCreationException
     * @throws GeneralSecurityException
     */
    protected static X509CRL generateCRL(PrivateKey caKey, X509Certificate caCert, X509Certificate revoked) throws OperatorCreationException, CRLException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        X500Name issuerDN = new X500Name(caCert.getIssuerDN().getName());

        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuerDN, new Date());

        // Build and sign CRL with CA private key
        ContentSigner sigGen = new JcaContentSignerBuilder(SHA_1_WITH_RSA_ENCRYPTION).setProvider(BOUNCYCASTLE_PROVIDER).build(caKey);

        // Add a single entry to CRL
        builder.addCRLEntry(revoked.getSerialNumber(), new Date(), CRLReason.aACompromise);

        X509CRLHolder crlHolder = builder.build(sigGen);

        X509CRL crl = new JcaX509CRLConverter()
                .setProvider(BOUNCYCASTLE_PROVIDER)
                .getCRL(crlHolder);

        crl.verify(caCert.getPublicKey());

        if (!crl.isRevoked(revoked)) {
            throw new RuntimeException("Certificate should have been revoked");
        }

        return crl;
    }

    protected static X509CRL generateCRL() throws GeneralSecurityException, OperatorCreationException {
        return generateCRL(idpPair.getPrivate(), rootCertificate, clientCertificates[0]);
    }

    protected static OCSPResponse generateCertificateCompromisedOCSPResponse() throws OperatorCreationException, OCSPException, IOException, CertificateEncodingException {
        DigestCalculator digestCalculator = createDigestCalculator();

        BasicOCSPRespBuilder ocspRespBuilder = new JcaBasicOCSPRespBuilder(rootCertificate.getPublicKey(), digestCalculator);

        BigInteger serialNumber = clientCertificates[0].getSerialNumber();
        JcaCertificateID certificateID = new JcaCertificateID(digestCalculator, rootCertificate, serialNumber);

        ocspRespBuilder.addResponse(certificateID, new RevokedStatus(new Date(), CRLReason.aACompromise));

        ContentSigner contentSigner = CertificateUtils.createSigner(idpPair.getPrivate());

        X509CertificateHolder[] chain = new X509CertificateHolder[] {
            new X509CertificateHolder(clientCertificates[0].getEncoded()),
            new X509CertificateHolder(clientCertificates[1].getEncoded())
        };
        BasicOCSPResp basicResp = ocspRespBuilder.build(contentSigner, chain, new Date());

        OCSPResp ocsResp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);
        OCSPResponse ocspResponse = ocsResp.toASN1Structure();

        return ocspResponse;
    }

    private static DigestCalculator createDigestCalculator() throws OperatorCreationException {
        JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
        digestCalculatorProviderBuilder.setProvider("BC");
        DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
        return digestCalculatorProvider.get(CertificateID.HASH_SHA1);
    }
}
